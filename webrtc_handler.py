"""
Cast Streaming (Cast Mirroring) receiver.

Despite the namespace name  urn:x-cast:com.google.cast.webrtc  Chrome does NOT
use WebRTC here.  It uses the Cast Streaming protocol:

  1.  Chrome sends OFFER with supportedStreams (audio + video), each containing
      an AES-128 key/IV-mask, SSRC, codec name, and RTP payload type.
  2.  We bind a UDP socket and reply with an ANSWER that includes the UDP port.
  3.  Chrome sends AES-128-CTR encrypted RTP packets to that port.
  4.  Each RTP packet carries a Cast extension header (RFC 5285 one-byte, ID=3)
      encoding  frame_id / packet_id / max_packet_id.
  5.  We reassemble packets into frames, decrypt with AES-128-CTR, then decode
      with PyAV and output audio (sounddevice) / video (JPEG frame callback).

Signaling messages on NS_WEBRTC:
  Chrome → Receiver:
    {"type":"OFFER",          "seqNum":N, "offer":{"castMode":"mirroring",
                                                    "supportedStreams":[...]}}
    {"type":"STATUS_REQUEST", "seqNum":N}
  Receiver → Chrome:
    {"type":"ANSWER",         "seqNum":N, "result":"ok",
                               "answer":{"castMode":"mirroring",
                                         "udpPort":PORT,
                                         "sendIndexes":[0,1],
                                         "ssrcs":[A_SSRC,V_SSRC]}}
    {"type":"STATUS_RESPONSE","seqNum":N, "result":"ok"}
"""

import io
import logging
import queue
import socket
import struct
import threading
import time
from typing import Any, Callable, Optional

log = logging.getLogger("CastStream")

# ── optional imports ───────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend as _crypto_backend
    _HAVE_CRYPTO = True
except ImportError:
    _HAVE_CRYPTO = False
    log.warning("[CastStream] cryptography not installed — decryption disabled")

try:
    import av as _av
    _HAVE_AV = True
except ImportError:
    _av: Any = None  # type: ignore[assignment]
    _HAVE_AV = False
    log.warning("[CastStream] PyAV (av) not installed — decoding disabled")

try:
    import sounddevice as sd
    import numpy as np
    _HAVE_SD = True
except ImportError:
    _HAVE_SD = False

try:
    import numpy as _np
    _HAVE_NP = True
except ImportError:
    _np = None  # type: ignore
    _HAVE_NP = False
    log.warning("[CastStream] numpy not installed — video output disabled")


# ── constants ──────────────────────────────────────────────────────────────────
_UDP_RECV_BUF   = 1 << 22   # 4 MB socket receive buffer
_UDP_RECV_SIZE  = 65_535
_FRAME_INTERVAL = 1.0 / 30  # max 30 fps to Electron
# Target display resolution sent to Electron (matches 1280×720 window at DPR=1).
# libav scales the decoded YUV before RGBA conversion so this is cheap.
# Cast Streaming uses RFC 5285 one-byte header extensions.
# The element ID defined in openscreen/cast (kCastExtensionId) is 15.
# Some older Chrome builds used ID 3 or 1.  We try all candidates.
_CAST_EXT_IDS   = {15, 3, 1, 4}  # accepted Cast extension element IDs
_RTCP_INTERVAL  = 0.5            # send RTCP RR every 500 ms


# ── codec-level RTP payload descriptor strippers ────────────────────────────────

def _strip_vp9_descriptor(data: bytes) -> bytes:
    """
    Strip the VP9 RTP payload descriptor (RFC 7741) from a single RTP payload
    chunk, returning only the raw VP9 bitstream bytes for that chunk.
    """
    if not data:
        return data
    off = 0
    b = data[off]; off += 1
    I = (b >> 7) & 1   # PictureID present
    L = (b >> 5) & 1   # Layer indices present
    F = (b >> 4) & 1   # Flexible mode
    V = (b >> 1) & 1   # Scalability structure present
    if I:
        pid = data[off]; off += 1
        if pid & 0x80:  # 15-bit PictureID
            off += 1
    if L:
        off += 2        # TID/SID/TL0PICIDX / TL0PICIDX ext
        if F:
            # Reference indices (variable): each byte's LSB=1 means more follow
            while off < len(data):
                ref = data[off]; off += 1
                if not (ref & 1):
                    break
    if V:
        if off >= len(data):
            return data
        ns = data[off]; off += 1             # number of spatial layers
        for _ in range((ns >> 5) + 1):
            if F:
                off += 2                     # frame resolution present
            pg = data[min(off, len(data)-1)] # protected group flags
            off += 1
            n_refs = (pg >> 5) & 0x3
            off += n_refs                    # reference IDs
    return data[off:]


def _strip_vp8_descriptor(data: bytes) -> bytes:
    """
    Strip the VP8 RTP payload descriptor (RFC 7741 predecessor, "draft-ietf-payload-vp8").
    """
    if not data:
        return data
    off = 0
    b = data[off]; off += 1
    X = (b >> 7) & 1   # Extension present
    if X:
        ext = data[off]; off += 1
        if (ext >> 7) & 1:  # I: PictureID present
            pid = data[off]; off += 1
            if pid & 0x80:
                off += 1   # 16-bit PID
        if (ext >> 6) & 1:  # L: TL0PICIDX present
            off += 1
        if (ext >> 5) & 1:  # T: TID present
            off += 1
        if (ext >> 4) & 1:  # K: KEYIDX present
            off += 1
    return data[off:]


_STRIP_FN = {
    "vp9": _strip_vp9_descriptor,
    "vp8": _strip_vp8_descriptor,
}  # keyed by codec name; other codecs pass payload through unchanged


def _parse_cast_payload_header(data: bytes):
    """
    Parse the Cast Streaming payload header embedded at the start of each RTP
    payload chunk when the RTP X-bit (extension) is not set.

    Chromium/OpenScreen Cast Streaming format
    (media/cast/net/rtp/rtp_packetizer.cc):

      Byte 0      : cast_flags
                      bit 7     : is_key_frame
                      bit 6     : has_reference_frame_id
                      bits 3-0  : num_extensions  (lower nibble)
      Byte 1      : frame_id        (uint8, wrapping)
      Bytes 2-3   : packet_id       (uint16 big-endian)  <- index of this chunk
      Bytes 4-5   : max_packet_id   (uint16 big-endian)  <- total packets - 1
      [Byte 6]    : reference_frame_id (uint8) — only if has_reference_frame_id
      [N extensions, each: 1-byte type + 1-byte data_len + data_len bytes]
      Remainder   : AES-CTR ciphertext (raw VP9/VP8 bitstream)

    Verified against real Chrome packets:
      c1 00 00 00 00 07 00 04 02 00 c8...
      └─┘ └─┘ └──┘ └──┘ └─┘ └──┘└─cipher
      flags fid pkt  max ref ext(t=4,l=2,d=00c8)
      → fid=0, pkt=0, max=7, cipher@11

    Returns (frame_id, packet_id, max_packet_id, ciphertext_offset)
    or None on error.
    """
    if len(data) < 6:
        return None
    cast_flags   = data[0]
    has_ref      = bool((cast_flags >> 6) & 1)
    num_ext      = cast_flags & 0x0F          # bits 3-0 = extension count
    frame_id     = data[1]                    # 8-bit wrapping frame ID
    packet_id    = struct.unpack_from(">H", data, 2)[0]
    max_pkt_id   = struct.unpack_from(">H", data, 4)[0]
    off = 6
    if has_ref:
        off += 1      # skip reference_frame_id byte
    for _ in range(num_ext):
        if off + 2 > len(data):
            break
        ext_data_len = data[off + 1]
        off += 2 + ext_data_len
    return frame_id, packet_id, max_pkt_id, off

# Preferred video codec order (first = best)
_VIDEO_PREF = ["av1", "vp9", "h264", "vp8", "hevc", "h265"]


# ── RTCP helpers ─────────────────────────────────────────────────────────────────
# Cast-specific application packet identifier
_CAST_RTCP_MAGIC = b"CAST"  # 4 bytes: 0x43 0x41 0x53 0x54
def _build_rtcp_rr(receiver_ssrc: int, sender_ssrc: int,
                   highest_seq: int = 0) -> bytes:
    """
    Build a minimal RTCP Receiver Report (RFC 3550 §6.4.2).
    receiver_ssrc : our SSRC (sender_ssrc + 1 as we advertised)
    sender_ssrc   : the SSRC of the stream we are reporting on
    """
    # Fixed header (1 word) + our SSRC (1 word) + 1 report block (6 words) = 8 words
    # length field = total 32-bit words - 1 = 7
    buf  = struct.pack(">BBH", 0x81, 201, 7)      # V=2,P=0,RC=1; PT=201; len=7
    buf += struct.pack(">I", receiver_ssrc)        # SSRC of this receiver
    buf += struct.pack(">I", sender_ssrc)          # SSRC being reported on
    buf += struct.pack(">I", 0)                    # frac_lost=0 | cum_lost=0
    buf += struct.pack(">I", highest_seq & 0xFFFFFFFF)  # extended highest seq
    buf += struct.pack(">I", 0)                    # inter-arrival jitter
    buf += struct.pack(">I", 0)                    # LSR
    buf += struct.pack(">I", 0)                    # DLSR
    return buf


def _build_rtcp_pli(receiver_ssrc: int, media_ssrc: int) -> bytes:
    """
    Build an RTCP PLI (Picture Loss Indication, RFC 4585 §6.3.1).
    Tells Chrome to send a video keyframe immediately.
    receiver_ssrc : our feedback SSRC (video sender SSRC + 1)
    media_ssrc    : Chrome's video SSRC
    """
    # V=2,P=0,FMT=1; PT=206 (PSFB); length=2 (4 words - 1)
    buf  = struct.pack(">BBH", 0x81, 206, 2)
    buf += struct.pack(">I", receiver_ssrc)  # packet sender SSRC (us)
    buf += struct.pack(">I", media_ssrc)     # media source SSRC (Chrome video)
    return buf


def _build_rtcp_fir(receiver_ssrc: int, media_ssrc: int,
                    seq: int = 1) -> bytes:
    """
    Build an RTCP FIR (Full Intra Request, RFC 5104 §4.3.1).
    PT=206, FMT=4.  Some Chrome versions require FIR rather than PLI
    to trigger the first video keyframe.
    """
    # V=2,P=0,FMT=4; PT=206; length=4 (5 words - 1)
    buf  = struct.pack(">BBH", 0x84, 206, 4)
    buf += struct.pack(">I", receiver_ssrc)      # SSRC of packet sender (us)
    buf += struct.pack(">I", 0)                  # media source = 0 for FIR
    buf += struct.pack(">I", media_ssrc)         # SSRC to request FIR for
    buf += struct.pack(">BBBB", seq & 0xFF, 0, 0, 0)  # seq number + 3 reserved bytes
    return buf


def _expand_frame_id(new_fid8: int, last_full_fid: int) -> int:
    """
    Expand an 8-bit wrapping Cast frame_id to a full 32-bit value.

    The Cast payload header carries only the low 8 bits of the frame counter
    (wraps 0-255).  The AES-128-CTR IV uses the full 32-bit value, so we must
    reconstruct the high bits from context.

    Algorithm: compute the forward 8-bit distance from the last 8-bit value;
    if it is < 128 (i.e. a plausible forward jump) the high bits may have
    incremented by one; if ≥ 128 treat it as a retransmission / out-of-order
    packet and keep the same high bits.
    """
    if last_full_fid < 0:
        return new_fid8          # very first frame
    last_fid8 = last_full_fid & 0xFF
    base      = last_full_fid - last_fid8   # high bits only
    candidate = base + new_fid8
    # Forward 8-bit distance (wrapping arithmetic)
    fwd_dist  = (new_fid8 - last_fid8) & 0xFF
    if fwd_dist > 0 and candidate <= last_full_fid:
        # new_fid8 wrapped past 255 — increment high byte
        candidate += 256
    return candidate


def _build_rtcp_remb(receiver_ssrc: int, media_ssrc: int,
                     bitrate_bps: int) -> bytes:
    """
    Build a REMB (Receiver Estimated Maximum Bitrate) RTCP packet.
    PT=206, FMT=15, unique identifier=b"REMB".
    Signals to Chrome's encoder that we can sustain the given bandwidth,
    pushing it to use higher quality / lower quantizer.
    """
    # Encode bitrate as: value = mantissa * 2^exp  (mantissa 18 bits, exp 6 bits)
    exp = 0
    mantissa = max(1, bitrate_bps)
    while mantissa > 0x3FFFF:   # 18-bit max = 262143
        mantissa >>= 1
        exp += 1
    # 6 words total → length field = 6 - 1 = 5
    buf  = struct.pack(">BBH", 0x8F, 206, 5)     # V=2|P=0|FMT=15, PT=206, len=5
    buf += struct.pack(">I", receiver_ssrc)        # SSRC of packet sender
    buf += struct.pack(">I", 0)                    # media source SSRC (0 per spec)
    buf += b"REMB"                                 # unique identifier
    buf += struct.pack(">I", (1 << 24) | ((exp & 0x3F) << 18) | (mantissa & 0x3FFFF))
    buf += struct.pack(">I", media_ssrc)           # SSRC of the targeted media source
    return buf


def _build_rtcp_cast_ack(receiver_ssrc: int, media_ssrc: int,
                         ack_frame_id: int,
                         nacks: Optional[list] = None) -> bytes:
    """
    Build a Cast-specific RTCP feedback message (PT=206, FMT=15) telling
    Chrome which video frame_id we last fully assembled, and optionally which
    later frames/packets are missing.

    Chrome's Cast Streaming sender (openscreen / Chromium media/cast) requires
    this message to advance its transmission window past acknowledged frames.
    Without it the sender loops retransmitting fid=0 forever.

    Format (openscreen rtcp_session.cc / rtcp_builder.cc):
      V=2,P=0,FMT=15  PT=206  length (32-bit words minus 1)
      SSRC of packet sender   (receiver SSRC = media_ssrc + 1)
      SSRC of media source    (Chrome sender SSRC)
      'C' 'A' 'S' 'T'         (magic 4 bytes)
      ack_frame_id  (1 byte)  highest fully-received Cast frame_id
      num_nack_fields (1 byte) number of NACK entries that follow
      [padding to 32-bit boundary]
      [nack entries: 1 byte frame_id_offset + 2 byte packet_bitmask each]

    nacks: list of (frame_id_offset: int, packet_bitmask: int) — optional.
    """
    if nacks is None:
        nacks = []
    # body = ack_id(1) + num_nacks(1) + nack entries (3 bytes each), padded to 4
    body = struct.pack("BB", ack_frame_id & 0xFF, len(nacks))
    for fid_offset, pkt_mask in nacks:
        body += struct.pack(">BH", fid_offset & 0xFF, pkt_mask & 0xFFFF)
    # Pad body to a multiple of 4 bytes
    if len(body) % 4:
        body += b"\x00" * (4 - len(body) % 4)
    # Total = 12-byte RTCP header + 4-byte CAST magic + body
    total_words = (12 + 4 + len(body)) // 4
    buf  = struct.pack(">BBH", 0x8F, 206, total_words - 1)  # V=2,P=0,FMT=15
    buf += struct.pack(">I", receiver_ssrc)
    buf += struct.pack(">I", media_ssrc)
    buf += _CAST_RTCP_MAGIC
    buf += body
    return buf


def _make_iv(iv_mask: bytes, frame_id: int) -> bytes:
    """AES-128-CTR IV = iv_mask XOR nonce, where nonce has frame_id at bytes 8-11.

    From openscreen frame_crypto.cc line 91:
        WriteBigEndian<uint32_t>(frame_id.lower_32_bits(), aes_nonce.data() + 8);
    i.e. the 32-bit frame_id is written big-endian at offset 8 in the 16-byte
    nonce (bytes 0-7 and 12-15 remain zero before XOR with iv_mask).

    For fid=0 this matches iv_mask exactly (XOR with all-zeros), which is why
    frame 0 decodes regardless of layout.  fid >= 1 require the correct offset.
    """
    counter = b"\x00" * 8 + struct.pack(">I", frame_id & 0xFFFFFFFF) + b"\x00" * 4
    return bytes(a ^ b for a, b in zip(iv_mask, counter))


def _decrypt_frame(key: bytes, iv_mask: bytes, frame_id: int, data: bytes) -> bytes:
    """Decrypt a reassembled Cast frame with AES-128-CTR (counter starts at 0)."""
    if not _HAVE_CRYPTO:
        return data
    iv = _make_iv(iv_mask, frame_id)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=_crypto_backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


# ── RTP parser ──────────────────────────────────────────────────────────────────
def _parse_rtp(raw: bytes):
    """
    Parse an RTP packet.  Returns
      (payload_type, ssrc, seq, timestamp, marker, payload,
       frame_id, packet_id, max_packet_id)
    or None on error.

    frame_id/packet_id/max_packet_id come from the Cast RTP extension
    (RFC 5285 one-byte header, element ID=3).  When absent they are all None
    and the caller should fall back to grouping by RTP timestamp + marker bit.
    """
    if len(raw) < 12:
        return None
    b0, b1 = raw[0], raw[1]
    if (b0 >> 6) != 2:                   # RTP version must be 2
        return None
    # Reject RTCP packets — PT 72-79 (masked) map to real RTCP types 200-207
    raw_pt = b1 & 0x7F
    if 72 <= raw_pt <= 79:
        return None  # RTCP packet — skip silently
    has_ext      = bool((b0 >> 4) & 1)
    cc           = b0 & 0xF
    marker       = bool((b1 >> 7) & 1)
    payload_type = b1 & 0x7F
    seq          = struct.unpack_from(">H", raw, 2)[0]
    timestamp    = struct.unpack_from(">I", raw, 4)[0]
    ssrc         = struct.unpack_from(">I", raw, 8)[0]
    offset       = 12 + cc * 4           # past fixed header + CSRC list

    frame_id = packet_id = max_packet_id = None

    if has_ext and len(raw) >= offset + 4:
        ext_profile   = struct.unpack_from(">H", raw, offset)[0]
        ext_len_words = struct.unpack_from(">H", raw, offset + 2)[0]
        body_start    = offset + 4
        body_end      = body_start + ext_len_words * 4
        offset        = body_end          # payload starts after extension

        if ext_profile == 0xBEDE:         # RFC 5285 one-byte header
            i = body_start
            while i < body_end:
                hdr = raw[i]
                if hdr == 0x00:           # padding
                    i += 1
                    continue
                if hdr == 0xFF:           # stop
                    break
                ext_id  = (hdr >> 4) & 0xF
                ext_len = (hdr & 0xF) + 1   # actual data bytes
                i += 1
                if ext_id in _CAST_EXT_IDS and ext_len >= 8 and i + ext_len <= body_end:
                    # Cast frame header: frame_id(4B) | packet_id(2B) | max_packet_id(2B)
                    frame_id      = struct.unpack_from(">I", raw, i)[0]
                    packet_id     = struct.unpack_from(">H", raw, i + 4)[0]
                    max_packet_id = struct.unpack_from(">H", raw, i + 6)[0]
                    # Log which ID was used on first discovery
                    if not hasattr(_parse_rtp, '_logged_cast_id'):
                        _parse_rtp._logged_cast_id = ext_id
                        log.info("[CastStream] Cast extension found: "
                                 "profile=0xBEDE id=%d frame_id=%d",
                                 ext_id, frame_id)
                    break  # found it — stop scanning
                i += ext_len
            if frame_id is None and not hasattr(_parse_rtp, '_logged_no_cast'):
                # Log once when 0xBEDE is present but no Cast element found
                _parse_rtp._logged_no_cast = True
                all_ids = []
                j = body_start
                while j < body_end:
                    hbyte = raw[j]
                    if hbyte in (0x00, 0xFF):
                        j += 1
                        continue
                    all_ids.append((hbyte >> 4) & 0xF)
                    j += 1 + (hbyte & 0xF) + 1
                log.info("[CastStream] 0xBEDE ext present but no Cast element "
                         "found; element IDs seen: %s", all_ids)
        else:
            # Log unknown extension profiles once to help diagnose format
            if not hasattr(_parse_rtp, '_logged_ext'):
                _parse_rtp._logged_ext = set()
            if ext_profile not in _parse_rtp._logged_ext:
                _parse_rtp._logged_ext.add(ext_profile)
                log.info("[CastStream] RTP ext profile=0x%04X len_words=%d "
                         "(expected 0xBEDE for Cast extension)",
                         ext_profile, ext_len_words)

    return (payload_type, ssrc, seq, timestamp, marker,
            raw[offset:], frame_id, packet_id, max_packet_id)


# ── stream config ─────────────────────────────────────────────────────────────────
class _StreamConfig:
    def __init__(self, d: dict):
        self.index   = d["index"]
        self.kind    = d["type"]          # "audio_source" | "video_source"
        self.codec   = d.get("codecName", "").lower()
        self.ssrc    = d["ssrc"]
        self.rtp_pt  = d.get("rtpPayloadType", 96)
        self.key     = bytes.fromhex(d["aesKey"])
        self.iv_mask = bytes.fromhex(d["aesIvMask"])
        self.channels    = d.get("channels", 2)
        parts = d.get("timeBase", "1/48000").split("/")
        self.sample_rate = int(parts[1]) if len(parts) == 2 and parts[0] == "1" else 48000
        # Maximum bitrate Chrome will encode at for this stream (bps).
        # We echo this back via REMB so Chrome uses its full budget.
        self.max_bitrate = d.get("maxBitrate", 4_000_000)


# ── frame reassembly buffers ─────────────────────────────────────────────────────────
class _FrameBuffer:
    """Buffer RTP packets by Cast frame_id and return complete frames."""

    def __init__(self):
        self._pkts: dict = {}   # frame_id → {packet_id: bytes}
        self._maxp: dict = {}   # frame_id → max_packet_id
        self._ready: dict = {}  # frame_id → assembled bytes (kept until superseded)

    def add(self, frame_id: int, packet_id: int, max_packet_id: int,
            payload: bytes) -> Optional[bytes]:
        """
        Add one RTP payload chunk.  Returns the full reassembled frame bytes
        (in packet order) when all chunks have arrived, otherwise None.

        Already-assembled frames are cached in _ready so that retransmissions
        of a single-packet frame (e.g. fid=1 pkt=0/0 sent 15× by Chrome)
        return the same bytes without re-assembling.  The cache entry is
        evicted by flush_stale() as soon as a newer frame_id arrives.
        """
        # Already assembled: return the cached bytes immediately
        if frame_id in self._ready:
            return self._ready[frame_id]
        if frame_id not in self._pkts:
            self._pkts[frame_id] = {}
            self._maxp[frame_id] = max_packet_id
        self._pkts[frame_id][packet_id] = payload
        total = self._maxp[frame_id] + 1
        if len(self._pkts[frame_id]) >= total:
            pkts = self._pkts.pop(frame_id)
            self._maxp.pop(frame_id, None)
            assembled = b"".join(pkts[i] for i in range(total))
            self._ready[frame_id] = assembled
            return assembled
        return None

    def flush_stale(self, current_fid: int, window: int = 64):
        stale = [fid for fid in self._pkts if (current_fid - fid) > window]
        for fid in stale:
            self._pkts.pop(fid, None)
            self._maxp.pop(fid, None)
        # Evict _ready entries that are older than current_fid — retransmissions
        # of those frames are no longer useful once a newer frame has arrived.
        stale_ready = [fid for fid in self._ready if fid < current_fid]
        for fid in stale_ready:
            self._ready.pop(fid, None)


class _TsFrameBuffer:
    """
    Fallback reassembly when the Cast RTP extension is absent.
    Groups packets by RTP timestamp; returns the assembled frame payload
    when a packet with the RTP marker bit (end-of-frame) arrives.
    """

    def __init__(self):
        # timestamp → list of (seq, payload) in arrival order
        self._pkts: dict = {}
        self._max_open = 8   # evict oldest after this many incomplete frames

    def add(self, timestamp: int, seq: int, marker: bool,
            payload: bytes) -> Optional[bytes]:
        if timestamp not in self._pkts:
            if len(self._pkts) >= self._max_open:
                oldest = next(iter(self._pkts))
                del self._pkts[oldest]
            self._pkts[timestamp] = []
        self._pkts[timestamp].append((seq, payload))
        if marker:
            pkts = self._pkts.pop(timestamp)
            pkts.sort(key=lambda x: x[0])
            # Handle 16-bit sequence wrap
            if len(pkts) > 1 and pkts[-1][0] - pkts[0][0] > 0x8000:
                pkts.sort(key=lambda x: (x[0] + 0x10000) & 0x1FFFF)
            return b"".join(p for _, p in pkts)
        return None


# ── main session class ───────────────────────────────────────────────────────────────
class CastWebRTCSession:
    """
    Manages a Cast Streaming session initiated by Chrome Tab/Audio Mirroring.

    The class name is kept as CastWebRTCSession for compatibility with
    receiver.py even though the underlying protocol is not WebRTC.

    Parameters
    ----------
    send_fn : callable(dict)
        Sends a JSON-serialisable dict back to Chrome on the webrtc namespace.
    is_audio_only : bool
        When True the video stream is ignored even if Chrome offers one.
    frame_callback : callable(bytes) or None
        Called with JPEG bytes for each decoded video frame (≤30 fps).
    """

    def __init__(self, send_fn: Callable, is_audio_only: bool = False,
                 frame_callback: Optional[Callable] = None):
        self._send_fn       = send_fn
        self._is_audio_only = is_audio_only
        self._frame_cb      = frame_callback

        self._udp_sock: Optional[socket.socket] = None
        self._stop          = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._rtcp_thread: Optional[threading.Thread] = None

        self._audio_cfg: Optional[_StreamConfig] = None
        # Only one video stream is accepted (best codec by _VIDEO_PREF)
        self._video_cfg: Optional[_StreamConfig] = None
        # Cast-extension-based reassembly (frame_id present)
        self._audio_buf  = _FrameBuffer()
        self._video_buf  = _FrameBuffer()
        # Fallback timestamp-based reassembly (frame_id absent)
        self._audio_ts_buf = _TsFrameBuffer()
        self._video_ts_buf = _TsFrameBuffer()

        self._audio_ctx = None
        self._video_ctx = None
        self._sd_stream = None

        # Sender address: learned from first incoming RTP packet
        self._sender_addr: Optional[tuple] = None
        # Per-stream seq tracking for RTCP RR
        self._audio_highest_seq: int = 0
        self._video_highest_seq: int = 0
        # Flag set when first video frame decoded (stops PLI spamming)
        self._got_video_frame: bool = False
        # FIR sequence number (must increment with every FIR sent to same SSRC)
        self._fir_seq: int = 0
        # Set to True if we discover video is not AES-encrypted
        self._video_no_decrypt: bool = False
        # Cast frame_id counter: starts at 0, increments per assembled video frame.
        # Used as the AES IV frame_id when the Cast RTP extension is absent.
        self._video_frame_id: int = 0
        self._audio_frame_id: int = 0
        # Last video/audio frame_id fully assembled (used in Cast RTCP ACK).
        # Starts at -1 (none received yet) so ACKs are sent only after assembly.
        self._last_ack_video_fid: int = -1
        self._last_ack_audio_fid: int = -1
        # Last EXPANDED (32-bit) video/audio frame_id seen; used to un-wrap the
        # 8-bit Cast header fid for the AES IV and _FrameBuffer keys.
        self._video_fid_full: int = -1
        self._audio_fid_full: int = -1
        # Codec failure streak counter and rate-limited log timestamp.
        self._vid_err_count: int = 0
        self._last_vid_err_log: float = 0.0
        # Last time we dispatched a video frame to the UI (rate limiter).
        self._last_video_frame_time: float = 0.0
        # Last fid that was fed to the codec; skip re-decoding the same frame.
        self._last_decoded_fid: int = -1
        # Frame dispatch worker: decouples recv_loop from WebSocket send latency.
        # _dispatch_latest holds the most-recent frame; the worker sends it.
        self._dispatch_latest: Optional[bytes] = None
        self._dispatch_lock   = threading.Lock()
        self._dispatch_event  = threading.Event()
        self._dispatch_thread: Optional[threading.Thread] = None
        # Video decode worker: VP9 decode + MJPEG encode run here so the
        # receive loop is never blocked and audio packets are read promptly.
        # Unbounded queue: we NEVER drop frames before they reach the VP9
        # decoder — skipping a reference frame corrupts all subsequent delta
        # frames until the next keyframe.  Rate-limiting happens at the MJPEG
        # output stage (inside _decode_video) not here.
        self._vid_dec_queue: queue.Queue = queue.Queue()
        self._vid_dec_thread: Optional[threading.Thread] = None
        # Audio playback worker: sd.write() is a blocking call; running it on
        # the receive thread stalls packet reading whenever the hardware buffer
        # is momentarily full, causing video decode queue bursts + VP9 glitches.
        # PCM samples are queued here and played from a dedicated thread.
        # maxlen=50 (~500 ms at 48 kHz/10 ms frames): if the playback thread
        # falls far behind we drop oldest chunks to stay low-latency.
        self._aud_play_queue: queue.Queue = queue.Queue(maxsize=50)
        self._aud_play_thread: Optional[threading.Thread] = None
        # Persistent MJPEG encoder; lazily created on first decoded frame.
        # Reused every frame to avoid codec init overhead (~20 ms).
        self._mjpeg_ctx: Optional[Any] = None

    # ── public API ───────────────────────────────────────────────────────────────────

    def handle_offer(self, offer: dict, seq_num: int):
        """Process Cast Streaming OFFER dict and send back ANSWER."""
        cast_mode    = offer.get("castMode", "mirroring")
        streams      = offer.get("supportedStreams", [])
        send_indexes = []
        answer_ssrcs = []

        # Collect candidates — only ONE video stream (best by _VIDEO_PREF)
        audio_stream = None
        video_candidates: dict[str, _StreamConfig] = {}   # codec → config
        for s in streams:
            cfg = _StreamConfig(s)
            if cfg.kind == "audio_source" and audio_stream is None:
                audio_stream = cfg
            elif cfg.kind == "video_source" and not self._is_audio_only:
                video_candidates[cfg.codec] = cfg

        if audio_stream:
            self._audio_cfg = audio_stream
            send_indexes.append(audio_stream.index)
            answer_ssrcs.append(audio_stream.ssrc + 1)
            log.info("[CastStream] Audio: codec=%s ssrc=%d sr=%d ch=%d idx=%d",
                     audio_stream.codec, audio_stream.ssrc,
                     audio_stream.sample_rate, audio_stream.channels, audio_stream.index)

        # Pick the best video codec offered
        chosen_video = None
        for pref in _VIDEO_PREF:
            if pref in video_candidates:
                chosen_video = video_candidates[pref]
                break
        if chosen_video is None and video_candidates:
            chosen_video = next(iter(video_candidates.values()))

        if chosen_video:
            self._video_cfg = chosen_video
            self._video_buf = _FrameBuffer()
            send_indexes.append(chosen_video.index)
            answer_ssrcs.append(chosen_video.ssrc + 1)
            log.info("[CastStream] Video selected: codec=%s ssrc=%d idx=%d maxBitrate=%d (rejected: %s)",
                     chosen_video.codec, chosen_video.ssrc, chosen_video.index,
                     chosen_video.max_bitrate,
                     [c for c in video_candidates if c != chosen_video.codec])

        # Bind UDP receive socket
        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, _UDP_RECV_BUF)
        except OSError:
            pass
        self._udp_sock.bind(("0.0.0.0", 0))
        self._udp_sock.settimeout(0.5)
        udp_port = self._udp_sock.getsockname()[1]
        log.info("[CastStream] Bound UDP on port %d", udp_port)

        answer = {
            "castMode":    cast_mode,
            "udpPort":     udp_port,
            "sendIndexes": send_indexes,
            "ssrcs":       answer_ssrcs,
        }
        self._send_fn({
            "type":   "ANSWER",
            "seqNum": seq_num,
            "result": "ok",
            "answer": answer,
        })
        log.info("[CastStream] ANSWER sent — udpPort=%d sendIndexes=%s ssrcs=%s",
                 udp_port, send_indexes, answer_ssrcs)

        self._open_codecs()
        self._stop.clear()
        self._dispatch_thread = threading.Thread(
            target=self._frame_dispatch_loop, daemon=True, name="CastStream-dispatch"
        )
        self._dispatch_thread.start()
        self._vid_dec_thread = threading.Thread(
            target=self._vid_dec_loop, daemon=True, name="CastStream-viddec"
        )
        self._vid_dec_thread.start()
        self._aud_play_thread = threading.Thread(
            target=self._aud_play_loop, daemon=True, name="CastStream-audplay"
        )
        self._aud_play_thread.start()
        self._thread = threading.Thread(
            target=self._recv_loop, daemon=True, name="CastStream-recv"
        )
        self._thread.start()
        self._rtcp_thread = threading.Thread(
            target=self._rtcp_loop, daemon=True, name="CastStream-rtcp"
        )
        self._rtcp_thread.start()

    def handle_status_request(self, seq_num: int):
        self._send_fn({"type": "STATUS_RESPONSE", "seqNum": seq_num, "result": "ok"})

    def close(self):
        self._stop.set()
        self._dispatch_event.set()  # wake dispatch thread so it can exit
        # Drain + sentinel so _vid_dec_loop unblocks even if queue was full.
        while not self._vid_dec_queue.empty():
            try: self._vid_dec_queue.get_nowait()
            except queue.Empty: break
        self._vid_dec_queue.put_nowait(None)
        # Sentinel for audio playback thread.
        try: self._aud_play_queue.put_nowait(None)
        except queue.Full: pass
        if self._thread:
            self._thread.join(timeout=3)
        if self._rtcp_thread:
            self._rtcp_thread.join(timeout=2)
        if self._dispatch_thread:
            self._dispatch_thread.join(timeout=2)
        if self._vid_dec_thread:
            self._vid_dec_thread.join(timeout=3)
        if self._aud_play_thread:
            self._aud_play_thread.join(timeout=2)
        for obj in ([self._udp_sock, self._sd_stream,
                      self._audio_ctx, self._video_ctx, self._mjpeg_ctx]):
            if obj:
                try: obj.close()
                except Exception: pass
        log.info("[CastStream] Session closed")

    # ── codecs ───────────────────────────────────────────────────────────────────────

    def _open_codecs(self):
        if not _HAVE_AV:
            return

        if self._audio_cfg:
            codec_name = {"opus": "opus", "aac": "aac", "mp3": "mp3"}.get(
                self._audio_cfg.codec, self._audio_cfg.codec)
            try:
                ctx = _av.CodecContext.create(codec_name, "r")
                ctx.sample_rate = self._audio_cfg.sample_rate
                # 'channels' is read-only in newer PyAV — use layout instead
                try:
                    ch = self._audio_cfg.channels
                    ctx.layout = "stereo" if ch == 2 else ("mono" if ch == 1 else "stereo")
                except Exception:
                    pass
                ctx.open()
                self._audio_ctx = ctx
                log.info("[CastStream] Audio codec opened: %s", codec_name)
            except Exception as e:
                log.warning("[CastStream] Audio codec %s failed: %s", codec_name, e)

        if _HAVE_SD and self._audio_cfg:
            try:
                # sd.default.device is (input, output); -1 means "not set".
                out_device = sd.default.device[1]
                if out_device == -1:
                    out_device = None   # let PortAudio pick the system default
                try:
                    dev_name = sd.query_devices(out_device)['name'] if out_device is not None else 'system default'
                except Exception:
                    dev_name = str(out_device)
                self._sd_stream = sd.OutputStream(
                    samplerate=self._audio_cfg.sample_rate,
                    channels=self._audio_cfg.channels,
                    dtype="float32",
                    device=out_device,
                )
                self._sd_stream.start()
                log.info("[CastStream] Audio output opened (%dHz, %dch) → device %s: %s",
                         self._audio_cfg.sample_rate, self._audio_cfg.channels,
                         out_device, dev_name)
            except Exception as e:
                log.warning("[CastStream] Audio output error: %s", e)
                # Last-resort: try with no device argument at all
                try:
                    self._sd_stream = sd.OutputStream(
                        samplerate=self._audio_cfg.sample_rate,
                        channels=self._audio_cfg.channels,
                        dtype="float32",
                    )
                    self._sd_stream.start()
                    log.info("[CastStream] Audio output opened (fallback, no device spec)")
                except Exception as e2:
                    log.warning("[CastStream] Audio output fallback also failed: %s", e2)

        # Open one codec context per video SSRC
        _codec_map = {"vp8": "vp8", "vp9": "vp9", "h264": "h264",
                      "av1": "av1", "hevc": "hevc", "h265": "hevc"}
        if self._video_cfg:
            codec_name = _codec_map.get(self._video_cfg.codec, self._video_cfg.codec)
            try:
                ctx = _av.CodecContext.create(codec_name, "r")
                ctx.open()
                self._video_ctx = ctx
                log.info("[CastStream] Video codec opened: %s (ssrc=%d)",
                         codec_name, self._video_cfg.ssrc)
            except Exception as e:
                log.warning("[CastStream] Video codec %s failed: %s", codec_name, e)

    # ── receive loop ──────────────────────────────────────────────────────────────────

    def _recv_loop(self):
        log.info("[CastStream] Receive loop started")
        first_pkt = True
        _loop_start = time.monotonic()
        _video_warned = False

        while not self._stop.is_set():
            try:
                raw, addr = self._udp_sock.recvfrom(_UDP_RECV_SIZE)
            except socket.timeout:
                continue
            except OSError:
                break

            # Learn the sender's address from the first packet so RTCP
            # feedback can be sent back.
            if self._sender_addr is None:
                self._sender_addr = addr
                log.info("[CastStream] Sender address: %s:%d", addr[0], addr[1])
                # Send PLI + FIR immediately to request first keyframe
                if self._video_cfg and self._udp_sock:
                    try:
                        self._fir_seq = (self._fir_seq + 1) & 0xFF
                        pli = _build_rtcp_pli(
                            self._video_cfg.ssrc + 1, self._video_cfg.ssrc)
                        fir = _build_rtcp_fir(
                            self._video_cfg.ssrc + 1, self._video_cfg.ssrc,
                            self._fir_seq)
                        self._udp_sock.sendto(pli, addr)
                        self._udp_sock.sendto(fir, addr)
                        log.info("[CastStream] PLI+FIR sent to request first keyframe")
                    except OSError:
                        pass

            result = _parse_rtp(raw)
            if result is None:
                continue
            pt, ssrc, seq, timestamp, marker, payload, frame_id, packet_id, max_packet_id = result

            if first_pkt:
                log.info("[CastStream] First RTP: ssrc=%d pt=%d len=%d",
                         ssrc, pt, len(payload))
                first_pkt = False

            # Periodic warning if video decoding never succeeds
            if not _video_warned and not self._got_video_frame:
                elapsed = time.monotonic() - _loop_start
                if elapsed > 10.0:
                    _video_warned = True
                    v_ssrc = self._video_cfg.ssrc if self._video_cfg else None
                    log.warning("[CastStream] No decoded video after %.0fs —"
                                " video_ssrc=%s", elapsed, v_ssrc)

            if not payload:
                continue

            # Route to audio or video
            if self._audio_cfg and ssrc == self._audio_cfg.ssrc:
                cfg      = self._audio_cfg
                ts_buf   = self._audio_ts_buf
                cast_buf = self._audio_buf
                is_video = False
                self._audio_highest_seq = seq
            elif self._video_cfg and ssrc == self._video_cfg.ssrc:
                cfg      = self._video_cfg
                ts_buf   = self._video_ts_buf
                cast_buf = self._video_buf
                is_video = True
                self._video_highest_seq = seq
            else:
                # Log unknown SSRCs at INFO for the first few — helps diagnose
                # Chrome sending video on an unexpected SSRC.
                if not hasattr(self, '_unknown_ssrcs'):
                    self._unknown_ssrcs: dict = {}
                if ssrc not in self._unknown_ssrcs:
                    self._unknown_ssrcs[ssrc] = 0
                self._unknown_ssrcs[ssrc] += 1
                if self._unknown_ssrcs[ssrc] <= 3:
                    log.info("[CastStream] Unknown SSRC %d pt=%d len=%d "
                             "(audio=%s video=%s)",
                             ssrc, pt, len(payload),
                             self._audio_cfg.ssrc if self._audio_cfg else 'none',
                             self._video_cfg.ssrc if self._video_cfg else 'none')
                continue

            if not payload:
                continue

            # ── Cast payload header (video + audio) ─────────────────────
            # Chrome ALWAYS embeds the Cast framing header at the very start of
            # the RTP payload, even when the RTP X-extension also carries the
            # framing info.  Strip it unconditionally so the bytes handed to
            # the AES decryptor are pure ciphertext.
            # If frame_id/packet_id/max_packet_id were already set from the RTP
            # extension (expanded 32-bit form), keep those values; otherwise
            # adopt the 8-bit values from the Cast payload header.
            result2 = _parse_cast_payload_header(payload)
            if result2 is None:
                if not is_video:
                    log.warning("[CastStream] AUD Cast header parse FAILED "
                                "payload[0:8]=%s len=%d",
                                payload[:8].hex(), len(payload))
                continue
            hdr_fid, hdr_pkt_id, hdr_max_pkt_id, c_off = result2
            payload = payload[c_off:]
            if not payload:
                if not is_video:
                    log.warning("[CastStream] AUD empty after Cast header strip "
                                "(c_off=%d total_before=%d)", c_off, c_off)
                continue
            if frame_id is None:
                frame_id      = hdr_fid
                packet_id     = hdr_pkt_id
                max_packet_id = hdr_max_pkt_id
            # Reassemble multi-packet frames.
            # Prefer Cast RTP extension frame_id; also works with frame_id
            # extracted from Cast payload header above.
            if frame_id is not None:
                # Expand 8-bit wire fid to full 32-bit using last-seen full fid.
                # This is critical for correct AES IV after fid wraps at 255→0.
                if is_video:
                    frame_id = _expand_frame_id(frame_id, self._video_fid_full)
                    if frame_id > self._video_fid_full:
                        self._video_fid_full = frame_id
                else:
                    frame_id = _expand_frame_id(frame_id, self._audio_fid_full)
                    if frame_id > self._audio_fid_full:
                        self._audio_fid_full = frame_id
                cast_buf.flush_stale(frame_id)
                raw_frame = cast_buf.add(frame_id, packet_id, max_packet_id, payload)
                if raw_frame is None:
                    continue   # still waiting for more packets
                aes_fid = frame_id
                if is_video:
                    # Send Cast RTCP ACK immediately so Chrome advances its
                    # transmission window and sends the next frame instead of
                    # retransmitting this one indefinitely.
                    if frame_id > self._last_ack_video_fid:
                        self._last_ack_video_fid = frame_id
                    ack_addr = self._sender_addr
                    if ack_addr and self._video_cfg and self._udp_sock:
                        try:
                            ack = _build_rtcp_cast_ack(
                                self._video_cfg.ssrc + 1,
                                self._video_cfg.ssrc,
                                self._last_ack_video_fid)
                            self._udp_sock.sendto(ack, ack_addr)
                        except OSError:
                            pass
                else:
                    # Audio also requires a Cast RTCP ACK — without it Chrome
                    # retransmits the same audio frame forever and stops
                    # advancing the audio stream.
                    if frame_id > self._last_ack_audio_fid:
                        self._last_ack_audio_fid = frame_id
                    ack_addr = self._sender_addr
                    if ack_addr and self._audio_cfg and self._udp_sock:
                        try:
                            ack = _build_rtcp_cast_ack(
                                self._audio_cfg.ssrc + 1,
                                self._audio_cfg.ssrc,
                                self._last_ack_audio_fid)
                            self._udp_sock.sendto(ack, ack_addr)
                        except OSError:
                            pass
            else:
                # Truly no framing info: reassemble by RTP timestamp + marker bit
                raw_frame = ts_buf.add(timestamp, seq, marker, payload)
                if raw_frame is None:
                    continue
                if is_video:
                    aes_fid = self._video_frame_id
                    self._video_frame_id += 1
                else:
                    aes_fid = self._audio_frame_id
                    self._audio_frame_id += 1

            dec_frame = _decrypt_frame(cfg.key, cfg.iv_mask, aes_fid, raw_frame)

            if is_video:
                # Skip re-decoding the same frame (Chrome retransmits last
                # packet of each fid; FrameBuffer returns cached bytes).
                if aes_fid <= self._last_decoded_fid:
                    continue
                self._last_decoded_fid = aes_fid
                try:
                    self._vid_dec_queue.put_nowait((dec_frame, raw_frame))
                except queue.Full:
                    # Decoder is temporarily behind — drop this frame for
                    # latency. Do NOT increment _vid_err_count: queue-full is
                    # not a decode failure; incrementing it would trigger
                    # spurious PLI+keyframe recovery every ~0.5 s.
                    log.warning("[CastStream] Video decode queue FULL — dropping frame fid=%d", aes_fid)
            else:
                self._decode_audio(dec_frame, aes_fid)

        log.info("[CastStream] Receive loop ended")

    # ── RTCP feedback loop ───────────────────────────────────────────────────────────

    def _rtcp_loop(self):
        """Send RTCP RR packets to Chrome every _RTCP_INTERVAL seconds.
        Also sends PLI every 2 s until the first decoded video frame arrives,
        to force Chrome to start the video stream with a keyframe.
        """
        log.info("[CastStream] RTCP feedback loop started")
        last_pli = 0.0
        _PLI_INTERVAL = 1.0
        while not self._stop.is_set():
            time.sleep(_RTCP_INTERVAL)
            addr = self._sender_addr
            if addr is None or self._udp_sock is None:
                continue
            try:
                if self._audio_cfg:
                    pkt = _build_rtcp_rr(
                        self._audio_cfg.ssrc + 1,
                        self._audio_cfg.ssrc,
                        self._audio_highest_seq,
                    )
                    self._udp_sock.sendto(pkt, addr)
                    # Periodic audio Cast RTCP ACK so Chrome doesn't stall the
                    # audio stream if an inline ACK was lost.
                    if self._last_ack_audio_fid >= 0:
                        ack = _build_rtcp_cast_ack(
                            self._audio_cfg.ssrc + 1,
                            self._audio_cfg.ssrc,
                            self._last_ack_audio_fid)
                        self._udp_sock.sendto(ack, addr)
                if self._video_cfg:
                    pkt = _build_rtcp_rr(
                        self._video_cfg.ssrc + 1,
                        self._video_cfg.ssrc,
                        self._video_highest_seq,
                    )
                    self._udp_sock.sendto(pkt, addr)
                    # Also send Cast RTCP ACK in the periodic loop so Chrome
                    # doesn't time out waiting if the recv_loop ACK was lost.
                    if self._last_ack_video_fid >= 0:
                        ack = _build_rtcp_cast_ack(
                            self._video_cfg.ssrc + 1,
                            self._video_cfg.ssrc,
                            self._last_ack_video_fid)
                        self._udp_sock.sendto(ack, addr)
                    # REMB: inform Chrome of our full bandwidth budget so its
                    # VP9 encoder uses a high bitrate (low quantizer = sharp text).
                    remb = _build_rtcp_remb(
                        self._video_cfg.ssrc + 1,
                        self._video_cfg.ssrc,
                        self._video_cfg.max_bitrate)
                    self._udp_sock.sendto(remb, addr)
                    # Also send PLI+FIR until first video frame decoded
                    now = time.monotonic()
                    if not self._got_video_frame and now - last_pli >= _PLI_INTERVAL:
                        self._fir_seq = (self._fir_seq + 1) & 0xFF
                        pli = _build_rtcp_pli(
                            self._video_cfg.ssrc + 1, self._video_cfg.ssrc)
                        fir = _build_rtcp_fir(
                            self._video_cfg.ssrc + 1, self._video_cfg.ssrc,
                            self._fir_seq)
                        self._udp_sock.sendto(pli, addr)
                        self._udp_sock.sendto(fir, addr)
                        last_pli = now
                        log.debug("[CastStream] PLI+FIR sent (awaiting first frame)")
            except OSError:
                break
        log.info("[CastStream] RTCP feedback loop ended")

    # ── decode ───────────────────────────────────────────────────────────────────────

    def _decode_audio(self, data: bytes, fid: int = -1):
        if not self._audio_ctx:
            log.warning("[CastStream] _decode_audio called but no audio_ctx (fid=%d)", fid)
            return
        if not self._sd_stream:
            log.warning("[CastStream] _decode_audio called but no sd_stream (fid=%d)", fid)
            return
        try:
            pkt = _av.Packet(data)
            frames_out = 0
            for frame in self._audio_ctx.decode(pkt):
                frames_out += 1
                arr = frame.to_ndarray()   # shape depends on format
                fmt = frame.format.name    # e.g. 'fltp', 's16', 's16p', 'flt'
                if fmt in ('s16', 's16p'):
                    arr = arr.astype('float32') / 32768.0
                elif fmt in ('s32', 's32p'):
                    arr = arr.astype('float32') / 2147483648.0
                else:
                    arr = arr.astype('float32')   # fltp / flt already [-1,1]
                # arr is (channels, samples) for planar, (1, ch*samples) for packed
                nch = frame.layout.nb_channels
                if fmt in ('s16', 's32', 'flt'):   # packed: interleave in last axis
                    arr = arr.reshape(-1, nch)
                else:                               # planar: (ch, samples) → (samples, ch)
                    arr = arr.T
                if arr.ndim == 1:
                    arr = arr.reshape(-1, 1)
                arr = np.ascontiguousarray(arr)
                # Put on playback queue instead of calling sd.write() directly.
                # sd.write() blocks when the hardware buffer is full; doing
                # that on the receive thread stalls UDP reads and causes VP9
                # reference-frame drops.  Drop oldest if the queue is full
                # (>50 frames = >500 ms backlog) to stay low-latency.
                try:
                    self._aud_play_queue.put_nowait(arr)
                except queue.Full:
                    try: self._aud_play_queue.get_nowait()
                    except queue.Empty: pass
                    try: self._aud_play_queue.put_nowait(arr)
                    except queue.Full: pass
        except Exception as e:
            log.warning("[CastStream] Audio decode error (fid=%d len=%d): %s", fid, len(data), e)

    # ── frame dispatch worker ───────────────────────────────────────────────────────

    def _frame_dispatch_loop(self):
        """Worker thread: sends the latest assembled frame over the WebSocket bridge.

        Runs independently of recv_loop so that a slow WebSocket send never
        blocks RTP packet processing or RTCP ACKs.  If frames arrive faster
        than the bridge can send them, older frames are silently dropped
        (latest-frame-wins) to maintain low display latency.
        """
        while not self._stop.is_set():
            self._dispatch_event.wait(timeout=0.1)
            self._dispatch_event.clear()
            with self._dispatch_lock:
                data = self._dispatch_latest
                self._dispatch_latest = None
            if data and self._frame_cb:
                try:
                    self._frame_cb(data)
                except Exception as _e:
                    log.debug("[CastStream] frame_cb error: %s", _e)

    def _aud_play_loop(self):
        """Dedicated audio playback thread.
        Pulls float32 numpy arrays from _aud_play_queue and writes them to
        sounddevice.  Keeping sd.write() off the receive thread ensures that
        a momentarily-full hardware buffer never stalls UDP packet reading.
        """
        while True:
            arr = self._aud_play_queue.get()
            if arr is None:   # sentinel from close()
                break
            if self._sd_stream:
                try:
                    self._sd_stream.write(arr)
                except Exception as e:
                    log.warning("[CastStream] sd.write error: %s "
                                "(shape=%s dtype=%s)",
                                e, arr.shape, arr.dtype)

    def _vid_dec_loop(self):
        """Worker thread: pulls (dec_frame, raw_frame) tuples from
        _vid_dec_queue and calls _decode_video. Keeps the UDP receive
        loop free to read audio packets without blocking on VP9/MJPEG."""
        while True:
            item = self._vid_dec_queue.get()
            if item is None:   # sentinel from close()
                break
            dec_frame, raw_frame = item
            try:
                self._decode_video(dec_frame, raw_frame)
            except Exception as e:
                log.warning("[CastStream] _vid_dec_loop exception: %s", e)

    def _decode_video(self, data: bytes, raw_data: bytes = b""):
        """
        Decode one assembled video frame.
        data     = AES-decrypted assembled stripped ciphertext
        raw_data = assembled stripped ciphertext before decryption (fallback)

        VP9/VP8 descriptors have already been stripped per-packet before
        assembly, so both data and raw_data are pure codec bitstreams
        (or their ciphertext equivalents).
        """
        if not self._video_ctx or not self._frame_cb:
            log.warning("[CastStream] _decode_video early exit: ctx=%s cb=%s",
                        bool(self._video_ctx), bool(self._frame_cb))
            return

        # Build candidate list: try decrypted first, raw fallback
        if self._video_no_decrypt:
            candidates = [(raw_data or data, "raw")]
        elif raw_data and raw_data != data:
            candidates = [(data, "decrypted"), (raw_data, "raw")]
        else:
            candidates = [(data, "decrypted")]

        for payload, label in candidates:
            if not payload:
                continue
            try:
                pkt = _av.Packet(payload)
                frames = list(self._video_ctx.decode(pkt))
                if frames:
                    frame = frames[0]
                    if not self._got_video_frame:
                        if label == "raw":
                            log.info("[CastStream] Video is not AES-encrypted"
                                     " - disabling decrypt for video stream")
                            self._video_no_decrypt = True
                        self._got_video_frame = True
                    self._vid_err_count = 0
                    # Rate-limit MJPEG encode: VP9 decode always runs (decoder
                    # state must stay continuous), but the expensive reformat +
                    # MJPEG encode is skipped for frames that won't be sent.
                    _now = time.monotonic()
                    if _now - self._last_video_frame_time < _FRAME_INTERVAL:
                        return  # decoded OK, just don't encode this frame
                    self._last_video_frame_time = _now
                    if (self._mjpeg_ctx is None
                            or self._mjpeg_ctx.width  != frame.width
                            or self._mjpeg_ctx.height != frame.height):
                        if self._mjpeg_ctx is not None:
                            try: self._mjpeg_ctx.close()
                            except Exception: pass
                        mctx = _av.CodecContext.create('mjpeg', 'w')
                        mctx.width   = frame.width
                        mctx.height  = frame.height
                        mctx.pix_fmt = 'yuvj420p'
                        mctx.options = {'qmin': '1', 'qmax': '1'}
                        mctx.open()
                        self._mjpeg_ctx = mctx
                        log.info("[CastStream] MJPEG encoder created: %dx%d qmin=1 qmax=1",
                                 frame.width, frame.height)
                    yuv  = frame.reformat(format='yuvj420p')
                    pkts = list(self._mjpeg_ctx.encode(yuv))
                    if not pkts:
                        return
                    jpeg_bytes = bytes(pkts[0])
                    with self._dispatch_lock:
                        self._dispatch_latest = jpeg_bytes
                    self._dispatch_event.set()
                    return
            except Exception as _ve:
                log.debug("[CastStream] decode exception (%s): %s",
                          label, _ve)
                continue

        # All candidates failed - log rate-limited and request keyframe recovery
        self._vid_err_count += 1
        now = time.monotonic()
        if now - self._last_vid_err_log > 1.0:
            self._last_vid_err_log = now
            log.info("[CastStream] Video decode failed - "
                     "dec[0:8]=%s raw[0:8]=%s",
                     data[:8].hex() if data else "empty",
                     raw_data[:8].hex() if raw_data else "n/a")
        # After 5 consecutive failures, recreate the codec context and send PLI
        # to force Chrome to transmit a new keyframe, recovering the decoder.
        if self._vid_err_count >= 5 and self._video_cfg:
            self._vid_err_count = 0
            self._got_video_frame = False
            log.info("[CastStream] Codec recovery: recreating VP9 context + PLI")
            try:
                if self._video_ctx:
                    self._video_ctx.close()
            except Exception:
                pass
            try:
                _codec_map = {"vp8": "vp8", "vp9": "vp9", "h264": "h264",
                              "av1": "av1", "hevc": "hevc", "h265": "hevc"}
                codec_name = _codec_map.get(self._video_cfg.codec,
                                            self._video_cfg.codec)
                ctx = _av.CodecContext.create(codec_name, "r")
                ctx.open()
                self._video_ctx = ctx
            except Exception as _ce:
                log.warning("[CastStream] Codec recreate failed: %s", _ce)
            # Send PLI + FIR to request a fresh keyframe
            addr = self._sender_addr
            if addr and self._udp_sock:
                try:
                    self._fir_seq = (self._fir_seq + 1) & 0xFF
                    pli = _build_rtcp_pli(
                        self._video_cfg.ssrc + 1, self._video_cfg.ssrc)
                    fir = _build_rtcp_fir(
                        self._video_cfg.ssrc + 1, self._video_cfg.ssrc,
                        self._fir_seq)
                    self._udp_sock.sendto(pli, addr)
                    self._udp_sock.sendto(fir, addr)
                except OSError:
                    pass
