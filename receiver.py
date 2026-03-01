"""
Cast V2 Receiver - Chromecast authentication test
Uses the extracted private key and certificate to serve as a Cast receiver.

This implements the Cast V2 TLS channel protocol including:
- TLS server on port 8009 (standard Chromecast port)
- Device authentication (AuthChallenge/AuthResponse)
- Connection channel (CONNECT/CLOSE)
- Heartbeat channel (PING/PONG)
- Receiver channel (GET_STATUS, LAUNCH, etc.)
"""

import ssl
import socket
import struct
import json
import threading
import logging
import hashlib
import os
import sys
import time
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Add parent path for protobuf import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cast_channel_pb2
from setup_server import cast_ipc
from webrtc_handler import CastWebRTCSession

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("CastReceiver")

# Cast V2 Namespaces
NS_CONNECTION = "urn:x-cast:com.google.cast.tp.connection"
NS_HEARTBEAT  = "urn:x-cast:com.google.cast.tp.heartbeat"
NS_RECEIVER   = "urn:x-cast:com.google.cast.receiver"
NS_AUTH       = "urn:x-cast:com.google.cast.tp.deviceauth"
NS_MEDIA      = "urn:x-cast:com.google.cast.media"
NS_WEBRTC     = "urn:x-cast:com.google.cast.webrtc"
NS_SETUP      = "urn:x-cast:com.google.cast.setup"
NS_DISCOVERY  = "urn:x-cast:com.google.cast.receiver.discovery"

# Chrome Tab/Audio Mirroring — use WebRTC directly, no IPC bridge
WEBRTC_APPS = {
    "0F5096E8",  # Chrome Tab Mirroring
    "85CDB22F",  # Chrome Audio Mirroring
}

# ---------------------------------------------------------------------------
# App Configs — loaded from the Chromecast baseconfig API
# APP_CONFIGS maps  app_id (str) -> receiver URL (str)
# Any app that has a URL in this dict is treated as an IPC app (loaded in
# the Electron webview which then connects to ws://localhost:8008/v2/ipc).
# ---------------------------------------------------------------------------

_BASECONFIG_URL   = "https://clients3.google.com/cast/chromecast/device/baseconfig"
_BASECONFIG_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "json.txt")


def _load_app_configs() -> dict:
    """Return a dict mapping app_id -> receiver URL.

    Fetches the Chromecast baseconfig from Google and caches the raw response
    to *json.txt* (next to this file).  Subsequent runs read from cache.
    The first line of the response is a XSSI protection prefix (')]}'\n') and
    is skipped before JSON parsing.
    """
    # --- fetch if cache is missing ---
    if not os.path.exists(_BASECONFIG_CACHE):
        log.info("APP_CONFIGS: Fetching baseconfig from %s", _BASECONFIG_URL)
        try:
            req = urllib.request.Request(
                _BASECONFIG_URL,
                headers={"User-Agent": "Mozilla/5.0 (CrKey armv7l 1.56.500000) "
                                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                                       "Chrome/56.0.2924.41 Safari/537.36 CrKey/1.56.500000"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
            with open(_BASECONFIG_CACHE, "wb") as fh:
                fh.write(raw)
            log.info("APP_CONFIGS: Cached baseconfig to %s", _BASECONFIG_CACHE)
        except Exception as exc:
            log.warning("APP_CONFIGS: Could not fetch baseconfig (%s) — using empty config", exc)
            return {}

    # --- read cache, skip first line (XSSI prefix) ---
    try:
        with open(_BASECONFIG_CACHE, "r", encoding="utf-8") as fh:
            fh.readline()          # skip  )]}'
            rest = fh.read()
        data = json.loads(rest)
    except Exception as exc:
        log.warning("APP_CONFIGS: Failed to parse baseconfig (%s) — using empty config", exc)
        return {}

    # --- walk the app list ---
    # Root may be a list directly or a dict with an 'applications' key.
    apps = data.get("applications", [])
    configs: dict = {}
    for app in apps:
        app_id = app.get("app_id", "")
        if app_id:
            configs[app_id] = app
    log.info("APP_CONFIGS: Loaded %d app URL(s) from baseconfig", len(configs))
    return configs


APP_CONFIGS: dict = _load_app_configs()

# ---------------------------------------------------------------------------
# Namespace cache — persists the sender-facing namespaces each IPC app reports
# so we can include them in the INITIAL RECEIVER_STATUS sent at LAUNCH time.
# Without this the sender locks in a namespace list at session-creation and
# throws invalid_parameter when the receiver tries to use an unlisted namespace.
# ---------------------------------------------------------------------------

_NS_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "namespace_cache.json")

# Internal-only namespaces that should NEVER be exposed to Cast senders.
_NS_SENDER_HIDDEN = {
    "urn:x-cast:com.google.cast.debugoverlay",
    "urn:x-cast:com.google.cast.inject",
    "urn:x-cast:com.google.cast.cac",
}


def _ns_cache_load() -> dict:
    """Load the persisted namespace cache from disk.  Returns {} on failure."""
    try:
        with open(_NS_CACHE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        log.info("NS_CACHE: Loaded namespace cache (%d app(s))", len(data))
        return data
    except FileNotFoundError:
        return {}
    except Exception as exc:
        log.warning("NS_CACHE: Failed to read cache (%s)", exc)
        return {}


def _ns_cache_save(cache: dict):
    """Persist the namespace cache to disk."""
    try:
        with open(_NS_CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2)
    except Exception as exc:
        log.warning("NS_CACHE: Failed to save cache (%s)", exc)


def _sender_namespaces(app_id: str, cache: dict) -> list:
    """Return the sender-facing namespace dicts for *app_id*.

    Uses the persisted cache when available; falls back to NS_MEDIA only.
    NS_MEDIA is always included.
    """
    cached = cache.get(app_id, [])
    ns_set = {NS_MEDIA}  # always present
    for ns in cached:
        if ns not in _NS_SENDER_HIDDEN and not ns.startswith("urn:x-cast:com.google.cast.tp"):
            ns_set.add(ns)
    return [{"name": ns} for ns in sorted(ns_set)]


# In-memory namespace cache (shared across CastReceiver instances)
_NS_CACHE: dict = _ns_cache_load()

def _fetch_app_metadata(app_id: str) -> dict:
    """Fetch metadata for a given app ID from the baseconfig API."""
    url = "https://clients3.google.com/cast/chromecast/device/app?a=" + app_id
    if not app_id:
        log.error("Cannot fetch metadata for empty app_id")
        return {}
    try:
        log.info("Getting metadata in APP_CONFIGS for app_id=%s", app_id)
        return APP_CONFIGS[app_id]
    except Exception:
        pass
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (CrKey armv7l 1.56.500000) "
                                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                                   "Chrome/56.0.2924.41 Safari/537.36 CrKey/1.56.500000"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.readline()  # skip XSSI prefix
            raw = resp.read()
        data = json.loads(raw.decode("utf-8", errors="ignore"))
        log.info("Fetched metadata for app_id=%s: %s", app_id, data.get("display_name", ""))
        APP_CONFIGS[app_id] = data  # cache it for future use
        return data
    except Exception as exc:
        log.warning("Failed to fetch metadata for app_id=%s: %s", app_id, exc)
        return {"url": "", "display_name": "Unknown App"}

class CastReceiver:
    """Minimal Cast V2 receiver with TLS authentication."""

    def __init__(self, cert_file, key_file, peer_cert_file=None, port=8009,
                 auth_crt_file=None, signatures_file=None, media_bridge=None,
                 friendly_name="Hiiragi Cast", device_id=None, audio_device=None):
        self.cert_file = cert_file
        self.key_file = key_file
        self.peer_cert_file = peer_cert_file
        self.auth_crt_file = auth_crt_file
        self.audio_device = audio_device
        self.signatures_file = signatures_file
        self.port = port
        self.friendly_name = friendly_name
        self.running = False
        self.clients = {}

        # Load private key and certificate for TLS
        with open(key_file, "rb") as f:
            key_data = f.read()
            if b"-----BEGIN" in key_data:
                self.private_key = serialization.load_pem_private_key(key_data, password=None)
            else:
                self.private_key = serialization.load_der_private_key(key_data, password=None)
                
        with open(cert_file, "rb") as f:
            cert_data = f.read()
            if b"-----BEGIN" in cert_data:
                self.cert_pem = cert_data
                self.cert = x509.load_pem_x509_certificate(self.cert_pem)
            else:
                self.cert = x509.load_der_x509_certificate(cert_data)
                self.cert_pem = self.cert.public_bytes(serialization.Encoding.PEM)
            self.cert_der = self.cert.public_bytes(serialization.Encoding.DER)

        # Load Device Auth Certificate (auth_crt)
        self.auth_cert_der = self.cert_der
        if auth_crt_file and os.path.exists(auth_crt_file):
            with open(auth_crt_file, "rb") as f:
                auth_data = f.read()
                if b"-----BEGIN" in auth_data:
                    self.auth_cert_der = x509.load_pem_x509_certificate(auth_data).public_bytes(serialization.Encoding.DER)
                else:
                    self.auth_cert_der = auth_data
            log.info("Loaded Device Auth Certificate (auth_crt) for bypass")

        # Load Pre-computed Signatures
        self.precomputed_signature = None
        if signatures_file and os.path.exists(signatures_file):
            with open(signatures_file, "rb") as f:
                raw = f.read()
            if signatures_file.endswith(".bin"):
                # Raw binary signature (from cert_fetch)
                self.precomputed_signature = raw
            else:
                # Legacy hex text format: "0x1c, 0xdc, ..."
                hex_values = [x.strip() for x in raw.decode(errors="ignore").split(",") if x.strip()]
                self.precomputed_signature = bytes([int(x, 16) for x in hex_values[:256]])
            log.info("Loaded pre-computed signature (%d bytes)", len(self.precomputed_signature))

        # Load intermediate/peer certs if available
        self.intermediate_certs_der = []
        if peer_cert_file and os.path.exists(peer_cert_file):
            with open(peer_cert_file, "rb") as f:
                pem_data = f.read()
            if b"-----BEGIN" in pem_data:
                # Parse all certificates in the file
                while b"-----BEGIN CERTIFICATE-----" in pem_data:
                    start = pem_data.find(b"-----BEGIN CERTIFICATE-----")
                    end = pem_data.find(b"-----END CERTIFICATE-----", start) + len(b"-----END CERTIFICATE-----")
                    cert_pem_block = pem_data[start:end]
                    cert_obj = x509.load_pem_x509_certificate(cert_pem_block)
                    self.intermediate_certs_der.append(
                        cert_obj.public_bytes(serialization.Encoding.DER)
                    )
                    pem_data = pem_data[end:]
            else:
                # Assume DER format
                self.intermediate_certs_der.append(pem_data)

        # Receiver state
        self.volume = {"level": 1.0, "muted": False}
        self.applications = []
        self.request_id = 0

        # Media state (one session at a time)
        self.media_session_id = 0
        self.media_status = None   # dict or None when idle
        self.media_transport_id = None  # transportId of the active app session

        # IPC app: track senders connected to the active transport
        self._ipc_sender_sockets: dict = {}  # sender_id -> (sock, transport_id)
        self._ipc_lock = threading.Lock()
        # Messages that arrived before the SDK connected — flushed on_sdk_ready
        self._ipc_pending: list = []  # list of (namespace, source_id, payload_utf8)

        # WebRTC session (Chrome Tab / Audio Mirroring)
        self._webrtc_session: CastWebRTCSession | None = None
        self._webrtc_sock = None          # Cast V2 socket for signaling back to Chrome
        self._webrtc_sender_id: str = ""  # Chrome's Cast source_id

        # Optional Electron media bridge
        self.bridge = media_bridge

        # Stable device ID — must match the mDNS `id` TXT record exactly
        # so the phone can correlate eureka_info / DEVICE_INFO with the mDNS entry.
        import hashlib as _hl, uuid as _uuid
        self.device_id = (device_id or
                          _hl.md5((friendly_name + str(_uuid.getnode())).encode())
                          .hexdigest().upper())

        log.info("Loaded certificate: %s", self.cert.subject)
        log.info("Certificate fingerprint (SHA256): %s",
                 self.cert.fingerprint(hashes.SHA256()).hex())
        log.info("Intermediate certificates loaded: %d", len(self.intermediate_certs_der))

    def _create_ssl_context(self):
        """Create TLS context mimicking a Chromecast."""
        import tempfile
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Write PEM to temp files for load_cert_chain
        with tempfile.NamedTemporaryFile(delete=False) as cert_tmp, \
             tempfile.NamedTemporaryFile(delete=False) as key_tmp:
            cert_tmp.write(self.cert_pem)
            cert_tmp.flush()
            
            key_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            key_tmp.write(key_pem)
            key_tmp.flush()
            
            ctx.load_cert_chain(certfile=cert_tmp.name, keyfile=key_tmp.name)
            
        os.unlink(cert_tmp.name)
        os.unlink(key_tmp.name)
        
        # Chromecast doesn't verify client certs
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Allow older TLS versions for compatibility
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def start(self):
        """Start the Cast receiver TLS server."""
        self.running = True
        ctx = self._create_ssl_context()

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", self.port))
        server_sock.listen(5)
        server_sock.settimeout(1.0)

        log.info("=" * 60)
        log.info("Cast V2 Receiver listening on port %d (TLS)", self.port)
        log.info("=" * 60)
        log.info("Waiting for Cast sender connections...")

        try:
            while self.running:
                try:
                    client_sock, addr = server_sock.accept()
                    log.info("New connection from %s:%d", addr[0], addr[1])
                    try:
                        tls_sock = ctx.wrap_socket(client_sock, server_side=True)
                        log.info("TLS handshake successful with %s:%d", addr[0], addr[1])
                        log.info("  TLS version: %s", tls_sock.version())
                        log.info("  Cipher: %s", tls_sock.cipher()[0])
                        # Handle client in separate thread
                        t = threading.Thread(
                            target=self._handle_client,
                            args=(tls_sock, addr),
                            daemon=True,
                        )
                        t.start()
                    except ssl.SSLError as e:
                        log.error("TLS handshake failed from %s: %s", addr[0], e)
                        client_sock.close()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            log.info("Shutting down...")
        finally:
            self.running = False
            server_sock.close()

    def _handle_client(self, tls_sock, addr):
        """Handle a single Cast client connection."""
        client_id = f"{addr[0]}:{addr[1]}"
        self.clients[client_id] = tls_sock
        tls_sock.settimeout(60.0)

        try:
            while self.running:
                # Read 4-byte length prefix (big endian)
                header = self._recv_exact(tls_sock, 4)
                if not header:
                    break
                msg_len = struct.unpack(">I", header)[0]
                if msg_len > 65536:
                    log.warning("Message too large (%d bytes), dropping", msg_len)
                    break

                # Read the protobuf message
                data = self._recv_exact(tls_sock, msg_len)
                if not data:
                    break

                msg = cast_channel_pb2.CastMessage()
                msg.ParseFromString(data)
                self._process_message(tls_sock, msg, client_id)

        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError) as e:
            log.info("Client %s disconnected: %s", client_id, e)
        finally:
            del self.clients[client_id]
            tls_sock.close()
            log.info("Connection closed: %s", client_id)

    def _recv_exact(self, sock, n):
        """Receive exactly n bytes from socket."""
        data = b""
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
            except (ConnectionResetError, ssl.SSLError):
                return None
        return data

    def _send_message(self, sock, msg):
        """Send a Cast message with length prefix."""
        data = msg.SerializeToString()
        header = struct.pack(">I", len(data))
        try:
            sock.sendall(header + data)
        except (BrokenPipeError, OSError, ssl.SSLError) as e:
            log.error("Failed to send message: %s", e)

    def _build_message(self, source_id, dest_id, namespace, payload_utf8=None, payload_binary=None):
        """Build a CastMessage."""
        msg = cast_channel_pb2.CastMessage()
        msg.protocol_version = cast_channel_pb2.CASTV2_1_0
        msg.source_id = source_id
        msg.destination_id = dest_id
        msg.namespace = namespace
        if payload_binary is not None:
            msg.payload_type = cast_channel_pb2.BINARY
            msg.payload_binary = payload_binary
        else:
            msg.payload_type = cast_channel_pb2.STRING
            msg.payload_utf8 = payload_utf8 or ""
        return msg

    def _process_message(self, sock, msg, client_id):
        """Process an incoming Cast message."""
        ns = msg.namespace
        src = msg.source_id
        dst = msg.destination_id

        if ns == NS_AUTH:
            log.info("[%s] << AUTH message (DeviceAuth challenge)", client_id)
            self._handle_auth(sock, msg)
        elif ns == NS_CONNECTION:
            payload = json.loads(msg.payload_utf8)
            log.info("[%s] << CONNECTION: %s", client_id, payload.get("type"))
            self._handle_connection(sock, msg, payload)
        elif ns == NS_HEARTBEAT:
            payload = json.loads(msg.payload_utf8)
            log.debug("[%s] << HEARTBEAT: %s", client_id, payload.get("type"))
            self._handle_heartbeat(sock, msg, payload)
        elif ns == NS_RECEIVER:
            payload = json.loads(msg.payload_utf8)
            log.info("[%s] << RECEIVER: %s", client_id, payload.get("type"))
            self._handle_receiver(sock, msg, payload)
        elif ns == NS_MEDIA:
            payload = json.loads(msg.payload_utf8)
            log.info("[%s] << MEDIA: %s", client_id, payload.get("type"))
            if self.applications and self._is_ipc_app(self.applications[0].get("appId", "")):
                if cast_ipc.is_connected:
                    log.info("[%s]  -> forwarding MEDIA to Cast SDK via IPC", client_id)
                    cast_ipc.send_message(ns, msg.source_id, msg.payload_utf8)
                else:
                    log.info("[%s]  -> buffering MEDIA (SDK not yet connected)", client_id)
                    self._ipc_pending.append((ns, msg.source_id, msg.payload_utf8))
            else:
                self._handle_media(sock, msg, payload)
        elif ns == NS_WEBRTC:
            payload = json.loads(msg.payload_utf8)
            log.info("[%s] << WEBRTC: %s", client_id, payload.get("type"))
            self._handle_webrtc(sock, msg, payload)
        elif ns == NS_SETUP:
            payload = json.loads(msg.payload_utf8)
            log.info("[%s] << SETUP: %s", client_id, payload.get("type"))
            self._handle_setup(sock, msg, payload)
        elif ns == NS_DISCOVERY:
            payload = json.loads(msg.payload_utf8)
            log.info("[%s] << DISCOVERY: %s", client_id, payload.get("type"))
            self._handle_discovery(sock, msg, payload)
        else:
            # For active IPC apps, forward any app-specific namespace to the SDK
            # instead of rejecting it.  This is needed for apps like Spotify that
            # use their own namespace 
            # alongside the standard media namespace.
            if (self.applications and
                    self._is_ipc_app(self.applications[0].get("appId", "")) and
                    msg.payload_type == cast_channel_pb2.STRING):
                log.info("[%s] << APP ns=%s  -> forwarding to IPC bridge",
                         client_id, ns.split(":")[-1])

                if cast_ipc.is_connected:
                    cast_ipc.send_message(ns, msg.source_id, msg.payload_utf8)
                else:
                    self._ipc_pending.append((ns, msg.source_id, msg.payload_utf8))
                return
            log.info("[%s] << UNKNOWN ns=%s", client_id, ns)
            if msg.payload_type == cast_channel_pb2.STRING:
                log.info("    payload: %s", msg.payload_utf8[:200])
                # Try to ACK with an error so the sender doesn't stall
                try:
                    p = json.loads(msg.payload_utf8)
                    rid = p.get("requestId")
                    if rid:
                        ack = {"type": "INVALID_REQUEST", "reason": "INVALID_COMMAND",
                               "requestId": rid}
                        self._send_message(sock, self._build_message(
                            msg.destination_id, msg.source_id, ns,
                            payload_utf8=json.dumps(ack)))
                except Exception:
                    pass

    def _handle_auth(self, sock, msg):
        """Handle device authentication challenge.
        
        The sender sends an AuthChallenge. We must respond with:
        - Our device certificate (DER)
        - Intermediate certificates (DER) 
        - A signature over the TLS peer certificate
        """
        auth_msg = cast_channel_pb2.DeviceAuthMessage()
        auth_msg.ParseFromString(msg.payload_binary)

        challenge = auth_msg.challenge
        sig_algo = challenge.signature_algorithm if challenge.HasField("signature_algorithm") else 1
        hash_algo = challenge.hash_algorithm if challenge.HasField("hash_algorithm") else 0
        sender_nonce = challenge.sender_nonce if challenge.HasField("sender_nonce") else b""

        log.info("  Auth challenge: sig_algo=%d hash_algo=%d nonce=%d bytes",
                 sig_algo, hash_algo, len(sender_nonce))

        # Get the TLS peer certificate from the socket
        # The signature is over the peer's TLS certificate DER bytes
        peer_cert_der = sock.getpeercert(binary_form=True)

        # Build the data to sign
        # For Chromecast auth: sign(peer_cert_der + sender_nonce)
        sign_data = b""
        if peer_cert_der:
            sign_data += peer_cert_der
        if sender_nonce:
            sign_data += sender_nonce

        # If no peer cert (which is normal since we don't require client certs),
        # sign just the nonce or empty data
        if not sign_data:
            sign_data = b""

        # Choose hash algorithm
        if hash_algo == 1:  # SHA256
            hash_alg = hashes.SHA256()
        else:  # SHA1 (default)
            hash_alg = hashes.SHA1()

        # Sign
        if self.precomputed_signature:
            signature = self.precomputed_signature
            log.info("  Using pre-computed signature (%d bytes)", len(signature))
        else:
            try:
                signature = self.private_key.sign(sign_data, padding.PKCS1v15(), hash_alg)
                log.info("  Signature computed (%d bytes, hash=%s)", len(signature), hash_alg.name)
            except Exception as e:
                log.error("  Signing failed: %s", e)
                # Send auth error
                err_response = cast_channel_pb2.DeviceAuthMessage()
                err_response.error.error_type = cast_channel_pb2.AuthError.INTERNAL_ERROR
                response_msg = self._build_message(
                    "receiver-0", msg.source_id, NS_AUTH,
                    payload_binary=err_response.SerializeToString()
                )
                self._send_message(sock, response_msg)
                return

        # Build AuthResponse
        auth_response = cast_channel_pb2.DeviceAuthMessage()
        auth_response.response.signature = signature
        auth_response.response.client_auth_certificate = self.auth_cert_der
        for int_cert in self.intermediate_certs_der:
            auth_response.response.intermediate_certificate.append(int_cert)
        auth_response.response.signature_algorithm = sig_algo
        
        # Only send sender_nonce if we actually signed it!
        # If we used a pre-computed signature, sending the nonce will cause Chrome
        # to verify the signature against the nonce, which will fail.
        if sender_nonce and not self.precomputed_signature:
            auth_response.response.sender_nonce = sender_nonce
            
        auth_response.response.hash_algorithm = hash_algo

        response_msg = self._build_message(
            "receiver-0", msg.source_id, NS_AUTH,
            payload_binary=auth_response.SerializeToString()
        )
        self._send_message(sock, response_msg)
        log.info("  >> AUTH response sent (cert=%d bytes, %d intermediates)",
                 len(self.cert_der), len(self.intermediate_certs_der))

    def _handle_connection(self, sock, msg, payload):
        """Handle connection namespace messages."""
        msg_type = payload.get("type")
        if msg_type == "CONNECT":
            log.info("  Client connected: dest=%s origin=%s",
                     msg.destination_id, payload.get("origin", ""))
            # If connecting to an IPC app transport, track the sender
            if (msg.destination_id == self.media_transport_id and
                    self.applications and
                    self._is_ipc_app(self.applications[0].get("appId", ""))):
                with self._ipc_lock:
                    self._ipc_sender_sockets[msg.source_id] = (sock, msg.destination_id)
                log.info("  Tracking IPC sender: src=%s dest=%s", msg.source_id, msg.destination_id)
                if cast_ipc.is_connected:
                    cast_ipc.send_sender_connected(msg.source_id)
            else:
                log.debug("  Not tracking CONNECT: dest=%s transport=%s ipc=%s",
                          msg.destination_id, self.media_transport_id,
                          self._is_ipc_app(self.applications[0].get("appId", ""))
                          if self.applications else False)
        elif msg_type == "CLOSE":
            log.info("  Client requested close: dest=%s", msg.destination_id)
            # If this sender was tracked, untrack and notify the SDK
            with self._ipc_lock:
                if msg.source_id in self._ipc_sender_sockets:
                    del self._ipc_sender_sockets[msg.source_id]
                    log.info("  IPC sender disconnected: %s", msg.source_id)
                    if cast_ipc.is_connected:
                        cast_ipc.send_sender_disconnected(msg.source_id)
            # If they closed the transport session, clear media state
            if msg.destination_id == self.media_transport_id:
                self.media_status = None
                self.media_transport_id = None
                log.info("  Media session cleared")

    def _handle_heartbeat(self, sock, msg, payload):
        """Handle heartbeat (PING/PONG)."""
        if payload.get("type") == "PING":
            pong = self._build_message(
                "receiver-0", msg.source_id, NS_HEARTBEAT,
                payload_utf8=json.dumps({"type": "PONG"})
            )
            self._send_message(sock, pong)
            log.debug("  >> PONG")

    def _handle_receiver(self, sock, msg, payload):
        """Handle receiver namespace messages."""
        msg_type = payload.get("type")
        request_id = payload.get("requestId", 0)

        if msg_type == "GET_STATUS":
            status = self._get_receiver_status()
            status["requestId"] = request_id
            response = self._build_message(
                "receiver-0", msg.source_id, NS_RECEIVER,
                payload_utf8=json.dumps(status)
            )
            self._send_message(sock, response)
            log.info("  >> RECEIVER_STATUS (requestId=%d)", request_id)

        elif msg_type == "LAUNCH":
            app_id = payload.get("appId", "CC1AD845")
            log.info("  Launch request for app: %s", app_id)
            # Use the same value for sessionId and transportId — real Chromecasts do
            # this, and it ensures that sender CONNECT messages (which use the
            # transportId from RECEIVER_STATUS) match self.media_transport_id.
            transport_id = hashlib.md5(os.urandom(16)).hexdigest()
            self.media_transport_id = transport_id
            self.media_status = None  # reset media on new launch
            app_name = _fetch_app_metadata(app_id).get("display_name", app_id)
            self.applications = [{
                "appId": app_id,
                "displayName": app_name,
                "isIdleScreen": False,
                "launchedFromCloud": False,
                "namespaces": _sender_namespaces(app_id, _NS_CACHE),
                "sessionId": transport_id,   # same as transportId
                "statusText": "Hiiragi Cast - " + app_name,
                "transportId": transport_id,
                "universalAppId": app_id,
            }]
            status = self._get_receiver_status()
            status["requestId"] = request_id
            response = self._build_message(
                "receiver-0", msg.source_id, NS_RECEIVER,
                payload_utf8=json.dumps(status)
            )
            self._send_message(sock, response)
            log.info("  >> RECEIVER_STATUS with launched app (transport=%s)", transport_id)
            if app_id in WEBRTC_APPS:
                # Chrome Tab/Audio Mirroring: no IPC bridge, WebRTC handles everything
                self._launch_webrtc_app(app_id, sock)
            elif _fetch_app_metadata(app_id).get("url"):
                # IPC app with a known receiver URL
                self._launch_ipc_app(app_id, launching_sender_id=msg.source_id)
            else:
                log.info("  No URL for app %s — running as bare Cast app", app_id)

        elif msg_type == "STOP":
            app_session_id = payload.get("sessionId")
            # Only stop if it matches the active session
            if app_session_id and self.applications and \
               self.applications[0].get("sessionId") == app_session_id:
                current_app_id = self.applications[0].get("appId", "")
                if current_app_id in WEBRTC_APPS:
                    self._stop_webrtc_app()
                elif current_app_id in APP_CONFIGS:
                    self._stop_ipc_app()
                self.applications = []
                self.media_status = None
                self.media_transport_id = None
            status = self._get_receiver_status()
            status["requestId"] = request_id
            response = self._build_message(
                "receiver-0", msg.source_id, NS_RECEIVER,
                payload_utf8=json.dumps(status)
            )
            self._send_message(sock, response)
            log.info("  >> RECEIVER_STATUS (app stopped)")

        elif msg_type == "SET_VOLUME":
            vol = payload.get("volume", {})
            if "level" in vol:
                self.volume["level"] = vol["level"]
            if "muted" in vol:
                self.volume["muted"] = vol["muted"]
            status = self._get_receiver_status()
            status["requestId"] = request_id
            response = self._build_message(
                "receiver-0", msg.source_id, NS_RECEIVER,
                payload_utf8=json.dumps(status)
            )
            self._send_message(sock, response)
            log.info("  >> RECEIVER_STATUS (volume updated)")

        elif msg_type == "GET_APP_AVAILABILITY":
            # Sender asks which app IDs are available on this receiver.
            # We report every requested app as available so any sender app can connect.
            app_ids = payload.get("appId", [])
            availability = {aid: "APP_AVAILABLE" for aid in app_ids}
            response = self._build_message(
                "receiver-0", msg.source_id, NS_RECEIVER,
                payload_utf8=json.dumps({
                    "type": "GET_APP_AVAILABILITY",
                    "availability": availability,
                    "requestId": request_id,
                })
            )
            self._send_message(sock, response)
            log.info("  >> GET_APP_AVAILABILITY: %s", list(availability.keys()))
            log.info("Prefetched metadata for available apps: %s", ", ".join(_fetch_app_metadata(aid).get("display_name", aid) for aid in availability.keys()))

        else:
            log.info("  Unhandled receiver message type: %s", msg_type)

    # ------------------------------------------------------------------ #
    #  IPC App helpers                                                     #
    # ------------------------------------------------------------------ #

    def _is_ipc_app(self, app_id: str) -> bool:
        """Return True if this app uses the /v2/ipc WebSocket channel."""
        return app_id in APP_CONFIGS and app_id not in WEBRTC_APPS

    def _is_webrtc_app(self, app_id: str) -> bool:
        """Return True if this app uses Chrome Tab/Audio Mirroring via WebRTC."""
        return app_id in WEBRTC_APPS

    def _launch_webrtc_app(self, app_id: str, sock):
        """Set up a WebRTC session for Chrome Tab/Audio Mirroring."""
        is_audio_only = (app_id == "85CDB22F")
        self._webrtc_sock = sock
        self._webrtc_sender_id = ""   # filled in on first WEBRTC message

        def send_fn(data: dict):
            """Send a WebRTC signaling message back to Chrome via Cast V2."""
            s = self._webrtc_sock
            target = self._webrtc_sender_id
            if not s or not target:
                return
            reply = self._build_message(
                self.media_transport_id, target, NS_WEBRTC,
                payload_utf8=json.dumps(data),
            )
            self._send_message(s, reply)

        frame_cb = self.bridge.send_mirror_frame if (self.bridge and not is_audio_only) else None

        try:
            self._webrtc_session = CastWebRTCSession(
                send_fn=send_fn,
                is_audio_only=is_audio_only,
                frame_callback=frame_cb,
                audio_device=self.audio_device,
            )
            log.info("[WebRTC] Session created for app %s (audio_only=%s)",
                     app_id, is_audio_only)
            if self.bridge:
                self.bridge.start_mirror()
        except RuntimeError as exc:
            log.error("[WebRTC] Cannot create session: %s", exc)

    def _stop_webrtc_app(self):
        """Tear down the active WebRTC session."""
        if self._webrtc_session:
            self._webrtc_session.close()
            self._webrtc_session = None
        self._webrtc_sock = None
        self._webrtc_sender_id = ""
        if self.bridge:
            self.bridge.stop_mirror()
        log.info("[WebRTC] Session stopped")

    def _handle_webrtc(self, sock, msg, payload):
        """Handle urn:x-cast:com.google.cast.webrtc messages from Chrome."""
        if not self._webrtc_session:
            log.warning("[WebRTC] Message received but no session active — ignoring")
            return
        # Keep the signaling socket and sender ID up-to-date
        self._webrtc_sock = sock
        self._webrtc_sender_id = msg.source_id

        msg_type = payload.get("type", "")
        seq_num  = payload.get("seqNum", 0)

        if msg_type == "OFFER":
            offer = payload.get("offer", {})
            streams = offer.get("supportedStreams", [])
            log.info("[CastStream] OFFER received (seq=%d, streams=%d)",
                     seq_num, len(streams))
            self._webrtc_session.handle_offer(offer, seq_num)

        elif msg_type == "GET_CAPABILITIES":
            # Respond with an empty capabilities dict so Chrome continues
            send_fn = getattr(self._webrtc_session, "_send_fn", None)
            if send_fn:
                send_fn({"type": "GET_CAPABILITIES_RESPONSE",
                         "seqNum": seq_num,
                         "result": "ok",
                         "remoteCapabilities": {
                             "video": {"supportedCodecs": ["vp8", "vp9", "h264"]},
                             "audio": {"supportedCodecs": ["opus", "aac"]},
                         }})
            log.info("[CastStream] GET_CAPABILITIES_RESPONSE sent")

        elif msg_type == "ICE_CANDIDATE":
            # Cast Streaming does not use ICE — ignore silently
            log.debug("[CastStream] ICE_CANDIDATE ignored (not used in Cast Streaming)")

        elif msg_type == "STATUS_REQUEST":
            self._webrtc_session.handle_status_request(seq_num)

        else:
            log.debug("[CastStream] Unhandled msg type: %s", msg_type)

    def _launch_ipc_app(self, app_id: str, launching_sender_id: str):
        """Load the receiver URL in Electron and wire the IPC bridge callbacks."""
        url = _fetch_app_metadata(app_id).get("url", "")
        if self.bridge:
            if url:
                device_name = self.friendly_name or "Cast Receiver"
                url = url.format(URL_ENCODED_FRIENDLY_NAME=device_name.replace(" ", "%20"))
            else:
                log.warning("[IPC] No URL found for app_id=%s — cannot launch IPC app", app_id)
                return
            log.info("[IPC] Loading receiver URL in Electron: %s", url[:80])
            self.bridge.load_url(url)

        # Reset the pending buffer for this new app session
        self._ipc_pending.clear()

        # Provide the app launch info so the IPC bridge can respond to the SDK's
        # "ready" handshake with the correct application context.
        app = self.applications[0] if self.applications else {}
        cast_ipc.launch_info = {
            "applicationId": app.get("appId", app_id),
            "applicationName": app.get("displayName", ""),
            "sessionId": app.get("sessionId", ""),
            "iconUrl": app.get("iconUrl", ""),
            "deviceCapabilities": {},
            "launchedFrom": "CAST",
            "launchingSenderId": launching_sender_id,
        }
        log.info("[IPC] launch_info set: appId=%s session=%s launchingSender=%s",
                 cast_ipc.launch_info["applicationId"],
                 cast_ipc.launch_info["sessionId"],
                 launching_sender_id)

        # Wire callbacks on the global IPC bridge singleton
        def on_sdk_ready():
            log.info("[IPC] SDK ready \u2014 sending senderConnected for tracked senders")
            # Update the running app's namespace list from what the SDK registered
            # so that RECEIVER_STATUS reflects app-specific namespaces (e.g. Spotify).
            if self.applications and cast_ipc.active_namespaces:
                # Filter to sender-facing namespaces only.
                ns_list = [{"name": ns} for ns in cast_ipc.active_namespaces
                           if ns not in _NS_SENDER_HIDDEN
                           and not ns.startswith("urn:x-cast:com.google.cast.tp")]
                # Always include NS_MEDIA
                if not any(n["name"] == NS_MEDIA for n in ns_list):
                    ns_list.append({"name": NS_MEDIA})
                self.applications[0]["namespaces"] = ns_list
                log.info("[IPC] Updated app namespaces: %s",
                         [n["name"].split(":")[-1] for n in ns_list])
                # Persist to namespace cache so future LAUNCH responses are correct.
                _NS_CACHE[app_id] = [n["name"] for n in ns_list]
                _ns_cache_save(_NS_CACHE)
                log.info("[IPC] Namespace cache updated for app %s", app_id)
                # Push an updated RECEIVER_STATUS to all tracked senders so they
                # learn about the app-specific namespace (e.g. Spotify's secure
                # namespace) before any messages arrive on it.
                updated_status = self._get_receiver_status()
                with self._ipc_lock:
                    sender_sockets = list(self._ipc_sender_sockets.items())
                for sid, info in sender_sockets:
                    if info:
                        try:
                            self._send_message(
                                info[0],
                                self._build_message(
                                    "receiver-0", sid, NS_RECEIVER,
                                    payload_utf8=json.dumps(updated_status)
                                )
                            )
                            log.info("[IPC] Pushed updated RECEIVER_STATUS \u2192 %s", sid)
                        except Exception as exc:
                            log.warning("[IPC] Failed to push RECEIVER_STATUS to %s: %s", sid, exc)
            with self._ipc_lock:
                senders = list(self._ipc_sender_sockets.keys())
            for sender_id in senders:
                cast_ipc.send_sender_connected(sender_id)
            # Flush messages that arrived before the SDK connected
            pending = self._ipc_pending[:]
            self._ipc_pending.clear()
            if pending:
                log.info("[IPC] Flushing %d buffered message(s) to SDK", len(pending))
            for (pns, psrc, ppayload) in pending:
                cast_ipc.send_message(pns, psrc, ppayload)

        def on_ipc_message(namespace, client_id, data):
            self._ipc_to_cast_v2(namespace, client_id, data)

        def on_sdk_disconnected():
            # self._stop_ipc_app()
            pass

        cast_ipc.on_sdk_ready = on_sdk_ready
        cast_ipc.on_message = on_ipc_message
        cast_ipc.on_sdk_disconnected = on_sdk_disconnected
        log.info("[IPC] IPC bridge configured for app %s", app_id)

    def _stop_ipc_app(self):
        """Tear down the IPC app: close the Electron window and clear callbacks."""
        cast_ipc.on_sdk_ready = None
        cast_ipc.on_message = None
        cast_ipc.launch_info = {}
        cast_ipc.disconnect()
        with self._ipc_lock:
            self._ipc_sender_sockets.clear()
        if self.bridge:
            self.bridge.stop_webview()
        log.info("[IPC] IPC app stopped")

    def _ipc_to_cast_v2(self, namespace: str, client_id: str, data: str):
        """Forward a message from the Cast SDK back to a Cast V2 sender."""
        transport_id = self.media_transport_id
        if not transport_id:
            log.debug("[IPC\u2192Cast] Dropping %s — no active transport", namespace)
            return

        with self._ipc_lock:
            # "*:*" means broadcast to all connected senders; empty also broadcasts
            if client_id and client_id != "*:*":
                targets = [(client_id, self._ipc_sender_sockets.get(client_id))]
            else:
                targets = list(self._ipc_sender_sockets.items())

        if not targets:
            log.warning("[IPC\u2192Cast] No tracked senders for %s (client_id=%r)",
                        namespace, client_id)
            return

        for sender_id, info in targets:
            if info is None:
                log.warning("[IPC\u2192Cast] No socket for sender %s — not connected via Cast V2",
                            sender_id)
                continue
            sock, _ = info
            try:
                msg = self._build_message(
                    transport_id, sender_id, namespace, payload_utf8=data
                )
                self._send_message(sock, msg)
                log.info("[IPC\u2192Cast] %s \u2192 %s", namespace.split(":")[-1], sender_id)
                log.debug("[IPC\u2192Cast] data: %s", data[:300])
            except Exception as exc:
                log.warning("[IPC\u2192Cast] Failed to send to %s: %s", sender_id, exc)

    def _handle_media(self, sock, msg, payload):
        """Handle media namespace messages."""
        msg_type = payload.get("type")
        request_id = payload.get("requestId", 0)
        transport_id = msg.destination_id  # e.g. "web-xxxxxx"

        if msg_type == "GET_STATUS":
            self._send_media_status(sock, msg.source_id, transport_id, request_id)

        elif msg_type == "LOAD":
            media = payload.get("media", {})
            autoplay = payload.get("autoplay", True)
            current_time = payload.get("currentTime", 0)

            self.media_session_id += 1
            self.media_transport_id = transport_id
            self.media_status = {
                "mediaSessionId": self.media_session_id,
                "playbackRate": 1,
                "playerState": "PLAYING" if autoplay else "PAUSED",
                "currentTime": current_time,
                "supportedMediaCommands": 274447,  # PAUSE|SEEK|STREAM_VOLUME|STREAM_MUTE|QUEUE_NEXT|QUEUE_PREV
                "volume": {"level": 1.0, "muted": False},
                "media": media,
                "currentItemId": 1,
                "extendedStatus": {},
                "repeatMode": "REPEAT_OFF",
                "idleReason": None,
            }
            log.info("  LOAD: contentId=%s type=%s",
                     media.get("contentId", ""), media.get("contentType", ""))
            self._send_media_status(sock, msg.source_id, transport_id, request_id)
            if self.bridge:
                self.bridge.on_load(media, current_time)

        elif msg_type == "PLAY":
            if self.media_status:
                self.media_status["playerState"] = "PLAYING"
                self.media_status["idleReason"] = None
            self._send_media_status(sock, msg.source_id, transport_id, request_id)
            if self.bridge:
                self.bridge.on_play()
            log.info("  >> PLAY")

        elif msg_type == "PAUSE":
            if self.media_status:
                self.media_status["playerState"] = "PAUSED"
            self._send_media_status(sock, msg.source_id, transport_id, request_id)
            if self.bridge:
                self.bridge.on_pause()
            log.info("  >> PAUSE")

        elif msg_type == "SEEK":
            current_time = payload.get("currentTime", 0)
            if self.media_status:
                self.media_status["currentTime"] = current_time
            self._send_media_status(sock, msg.source_id, transport_id, request_id)
            if self.bridge:
                self.bridge.on_seek(current_time)
            log.info("  >> SEEK to %.1fs", current_time)

        elif msg_type == "STOP":
            if self.media_status:
                self.media_status["playerState"] = "IDLE"
                self.media_status["idleReason"] = "CANCELLED"
            self._send_media_status(sock, msg.source_id, transport_id, request_id)
            self.media_status = None
            if self.bridge:
                self.bridge.on_stop()
            log.info("  >> MEDIA STOP")

        elif msg_type == "SET_VOLUME":
            vol = payload.get("volume", {})
            if self.media_status:
                if "level" in vol:
                    self.media_status["volume"]["level"] = vol["level"]
                if "muted" in vol:
                    self.media_status["volume"]["muted"] = vol["muted"]
            self._send_media_status(sock, msg.source_id, transport_id, request_id)
            if self.bridge:
                mv = self.media_status["volume"] if self.media_status else {}
                self.bridge.on_volume(mv.get("level", 1.0), mv.get("muted", False))
            log.info("  >> MEDIA SET_VOLUME")

        elif msg_type == "QUEUE_LOAD":
            items = payload.get("items", [])
            log.info("  QUEUE_LOAD: %d items", len(items))
            if items:
                item = items[0]
                media = item.get("media", {})
                start_time = item.get("startTime", 0)
                self.media_session_id += 1
                self.media_transport_id = transport_id
                self.media_status = {
                    "mediaSessionId": self.media_session_id,
                    "playbackRate": 1,
                    "playerState": "PLAYING",
                    "currentTime": start_time,
                    "supportedMediaCommands": 274447,
                    "volume": {"level": 1.0, "muted": False},
                    "media": media,
                    "currentItemId": item.get("itemId", 1),
                    "repeatMode": payload.get("repeatMode", "REPEAT_OFF"),
                    "idleReason": None,
                }
                log.info("  QUEUE_LOAD: contentId=%s type=%s",
                         media.get("contentId", ""), media.get("contentType", ""))
                if self.bridge:
                    self.bridge.on_load(media, start_time)
            self._send_media_status(sock, msg.source_id, transport_id, request_id)

        elif msg_type == "QUEUE_INSERT":
            log.info("  QUEUE_INSERT: %d items", len(payload.get("items", [])))
            self._send_media_status(sock, msg.source_id, transport_id, request_id)

        elif msg_type == "QUEUE_REMOVE":
            log.info("  QUEUE_REMOVE")
            self._send_media_status(sock, msg.source_id, transport_id, request_id)

        elif msg_type == "QUEUE_NEXT" or msg_type == "QUEUE_PREV":
            log.info("  %s", msg_type)
            self._send_media_status(sock, msg.source_id, transport_id, request_id)

        elif msg_type == "EDIT_TRACKS_INFO":
            # Sender is enabling/disabling subtitle or audio tracks.
            # Store active track IDs and style in media status, then ack.
            active_ids = payload.get("activeTrackIds", [])
            track_style = payload.get("textTrackStyle", None)
            if self.media_status:
                self.media_status["activeTrackIds"] = active_ids
                if track_style is not None:
                    self.media_status["textTrackStyle"] = track_style
            log.info("  EDIT_TRACKS_INFO: activeTrackIds=%s", active_ids)
            self._send_media_status(sock, msg.source_id, transport_id, request_id)

        else:
            log.info("  Unhandled media message: %s", msg_type)
            # Still send an empty status so the sender doesn't stall
            self._send_media_status(sock, msg.source_id, transport_id, request_id)

    def _send_media_status(self, sock, dest, transport_id, request_id=0):
        """Send MEDIA_STATUS response."""
        status_list = []
        if self.media_status:
            entry = dict(self.media_status)
            if entry.get("idleReason") is None:
                del entry["idleReason"]   # omit when not idle
            status_list = [entry]
        media_status = {
            "type": "MEDIA_STATUS",
            "status": status_list,
            "requestId": request_id,
        }
        response = self._build_message(
            transport_id, dest, NS_MEDIA,
            payload_utf8=json.dumps(media_status)
        )
        self._send_message(sock, response)

    def _handle_discovery(self, sock, msg, payload):
        """Handle urn:x-cast:com.google.cast.receiver.discovery messages."""
        msg_type = payload.get("type", "")
        request_id = payload.get("requestId", 0)

        if msg_type == "GET_DEVICE_INFO":
            device_info = {
                "type": "DEVICE_INFO",
                "requestId": request_id,
                "deviceInfo": {
                    "deviceId": self.device_id.lower(),
                    "friendlyName": self.friendly_name,
                    "model": "Chromecast",
                    "productName": "Chromecast",
                    "manufacturer": "Google Inc.",
                    "macAddress": "11:22:33:44:55:66",
                    "releaseTrack": "stable-channel",
                    "buildVersion": "1.56.330094",
                    "castBuildRevision": "1.56.330094",
                    "capabilities": 4101,
                    "version": 12,
                    "locale": "en",
                },
            }
            self._send_message(sock, self._build_message(
                msg.destination_id, msg.source_id, NS_DISCOVERY,
                payload_utf8=json.dumps(device_info)))
            log.info("  >> DEVICE_INFO response sent")

    def _device_id(self):
        return self.device_id

    def _handle_setup(self, sock, msg, payload):
        """Handle urn:x-cast:com.google.cast.setup messages.

        The Google Home app sends an 'eureka_info' request over the Cast TLS
        channel asking for device details.  Without a proper response the app
        shows the device as unresponsive and won't let the user cast to it.
        """
        msg_type = payload.get("type", "")
        request_id = payload.get("request_id", payload.get("requestId", 0))

        if msg_type == "eureka_info":
            # Build the same JSON as the HTTP /setup/eureka_info endpoint.
            # The 'data' field in the request tells us which fields are wanted;
            # we just return everything — the app ignores unknown keys.
            info = {
                "bssid": "11:22:33:44:55:66",
                "build_version": "1.56.330094",
                "cast_build_revision": "1.56.330094",
                "connected": True,
                "ethernet_connected": False,
                "has_update": False,
                "locale": "en",
                "model_name": "Chromecast",
                "multizone": {"audio_output_delay": 0,
                               "audio_output_delay_oem": 0,
                               "aux_in_enabled": False},
                "name": self.friendly_name,
                "opt_in": {"crash": False, "opencast": False, "stats": False},
                "release_track": "stable-channel",
                "setup_state": 4,
                "sign": {"certificate": "", "intermediate_certs": [],
                          "nonce": "", "signed_data": ""},
                "tos_accepted": True,
                "version": 12,
                "uma_client_id": self.device_id.lower(),
                "uuid": self.device_id.lower(),
                "wpa_configured": True,
                "wpa_state": 10,
                "device_info": {
                    "manufacturer": "Google Inc.",
                    "product_name": "Chromecast",
                    "ssdp_udn": self.device_id.lower(),
                },
                "build_info": {
                    "build_type": 3,
                    "cast_build_revision": "1.56.330094",
                },
            }
            response = {
                "type": "eureka_info",
                "request_id": request_id,
                "status": "success",
                "data": info,
            }
            self._send_message(sock, self._build_message(
                msg.destination_id, msg.source_id, NS_SETUP,
                payload_utf8=json.dumps(response)))
            log.info("  >> eureka_info response sent")

    def _get_receiver_status(self):
        """Build receiver status response."""
        return {
            "type": "RECEIVER_STATUS",
            "status": {
                "applications": self.applications,
                "isActiveInput": True,
                "isStandBy": False,
                "volume": {
                    "controlType": "attenuation",
                    "level": self.volume["level"],
                    "muted": self.volume["muted"],
                    "stepInterval": 0.05,
                },
            },
        }
