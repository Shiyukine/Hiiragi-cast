"""
Certificate fetcher — retrieves live Cast TLS credentials from the remotetogo API.

The API returns fresh certificates that are valid for the current time window
(nb/na = not-before / not-after as Unix timestamps).  All credential fields
are base64(DER) and are saved to a local `certs/` directory as PEM / binary so
the rest of the code can use them without needing the API key at run-time.

Fields returned by the API:
  nb     – not-before Unix timestamp
  na     – not-after  Unix timestamp
  cpu    – auth/device cert (Google-signed, base64 DER)
  ica    – intermediate CA cert (base64 DER)
  pub    – TLS cert (dynamically generated, base64 DER)
  pri    – TLS private key (base64 DER, PKCS#1)
  sha1   – pre-computed SHA-1  signature (base64 raw bytes)
  sha256 – pre-computed SHA-256 signature (base64 raw bytes)
  now    – server Unix timestamp
"""

import base64
import hashlib
import json
import logging
import os
import time
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import serialization

log = logging.getLogger("CertFetch")

# ── API config ────────────────────────────────────────────────────────────────
_API_SALT = "78b1ad1dcd88176a954c03b38cbb962c"
_API_BASE = "https://cast.remotetogo.com/api/v1/cks"


def _api_url() -> str:
    ts = str(int(time.time()))
    sig = hashlib.md5((_API_SALT + ts).encode()).hexdigest()
    return f"{_API_BASE}?ts={ts}&sig={sig}"


def _der_to_pem_cert(der: bytes) -> bytes:
    cert = x509.load_der_x509_certificate(der)
    return cert.public_bytes(serialization.Encoding.PEM)


# ── Public API ────────────────────────────────────────────────────────────────

def fetch_certs(certs_dir: str, force: bool = False) -> dict:
    """Fetch certificates from the API and save them to *certs_dir*.

    Returns a dict with keys:
      cert, key, auth_crt, intermediate, sig_sha256, sig_sha1,
      not_before, not_after

    If cached certs are still valid (not_after - 1 h > now) they are reused
    unless *force* is True.
    """
    os.makedirs(certs_dir, exist_ok=True)
    meta_path = os.path.join(certs_dir, "meta.json")

    # ── Check cache ───────────────────────────────────────────────────────────
    if not force and os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)
        not_after = meta.get("not_after", 0)
        # Keep cached if cert is still valid for at least 1 hour
        if not_after - time.time() > 3600:
            log.info("Using cached certificates (valid until %s)",
                     time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(not_after)))
            return {
                "cert":         os.path.join(certs_dir, "tls.pem"),
                "key":          os.path.join(certs_dir, "pk.pem"),
                "auth_crt":     os.path.join(certs_dir, "auth.pem"),
                "intermediate": os.path.join(certs_dir, "intermediate.pem"),
                "sig_sha256":   os.path.join(certs_dir, "sig_sha256.bin"),
                "sig_sha1":     os.path.join(certs_dir, "sig_sha1.bin"),
                "not_before":   meta["not_before"],
                "not_after":    not_after,
            }

    # ── Fetch from API ────────────────────────────────────────────────────────
    url = _api_url()
    log.info("Fetching certificates from API...")
    log.debug("URL: %s", url)
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        raise RuntimeError(f"Certificate API request failed: {exc}") from exc

    # ── Decode & decrypt ──────────────────────────────────────────────────────
    # The API XOR-encrypts every field with a fixed keystream (an API secret
    # that never rotates independently of the cert).  The keystream is stored in
    # keystream.bin, derived once from the known-plaintext private key (pk.pem)
    # when the certs were first captured.  Fallback: derive the first 907 bytes
    # from intermediate.der XOR enc_ica (sufficient for all fields except pri).
    def b64(field: str) -> bytes:
        raw = data[field]
        padding = (4 - len(raw) % 4) % 4
        return base64.b64decode(raw + "=" * padding)

    _here = os.path.dirname(os.path.abspath(__file__))
    ks_path = os.path.join(_here, "data", "keystream.bin")

    if os.path.exists(ks_path):
        with open(ks_path, "rb") as f:
            keystream = f.read()
        log.debug("Loaded %d-byte keystream from keystream.bin", len(keystream))
    else:
        # Derive 907-byte keystream from the known Eureka Gen1 ICA cert.
        # This only suffices for fields <= 907 bytes (ica/cpu/pub/sha*).
        # The pri field (1704 bytes) won't decrypt correctly without keystream.bin.
        known_ica_path = os.path.join(_here, "data", "intermediate.der")
        if not os.path.exists(known_ica_path):
            raise RuntimeError(
                f"Neither keystream.bin nor intermediate.der found in {_here}. "
                "At least one is required for API decryption."
            )
        with open(known_ica_path, "rb") as f:
            known_ica_der = f.read()
        encrypted_ica = b64("ica")
        if len(encrypted_ica) != len(known_ica_der):
            raise RuntimeError(
                f"ICA length mismatch: API {len(encrypted_ica)}B vs disk {len(known_ica_der)}B. "
                "intermediate.der may be for a different device generation."
            )
        keystream = bytes(a ^ b for a, b in zip(encrypted_ica, known_ica_der))
        log.warning(
            "keystream.bin not found — using 907-byte ICA-derived keystream. "
            "Private key decryption will be incomplete. "
            "Place the correct pk.pem in %s and run cert_fetch.py to generate keystream.bin.",
            _here,
        )

    def decrypt(field: str) -> bytes:
        """XOR-decrypt an API field using the keystream."""
        enc = b64(field)
        if len(enc) > len(keystream):
            log.warning(
                "Field '%s' (%dB) exceeds keystream length (%dB); tail may be incorrect.",
                field, len(enc), len(keystream),
            )
        return bytes(enc[i] ^ keystream[i % len(keystream)] for i in range(len(enc)))

    def decrypt_pri(field: str) -> bytes:
        """XOR-decrypt the private key field.

        If the ciphertext is longer than the keystream, the missing keystream
        bytes are recovered from the known PEM footer
        (``-----END PRIVATE KEY-----\\n``) which is always at the very end of a
        PKCS#8 PEM key.  The keystream is extended in memory **and** written back
        to ``keystream.bin`` so subsequent runs are covered automatically.
        """
        nonlocal keystream
        enc = b64(field)
        extra = len(enc) - len(keystream)

        if extra > 0:
            # The last 26 bytes of any PKCS#8 PEM key are the fixed footer.
            pem_footer = b"-----END PRIVATE KEY-----\n"
            if extra > len(pem_footer):
                raise RuntimeError(
                    f"Field '{field}' ({len(enc)}B) exceeds keystream by {extra}B, "
                    f"which is more than the known PEM footer ({len(pem_footer)}B). "
                    "Cannot auto-extend keystream; please capture a fresh pk.pem."
                )
            # The trailing `extra` bytes of the plaintext are the last `extra`
            # bytes of the PEM footer.
            known_tail = pem_footer[-extra:]
            tail_enc   = enc[len(keystream):]
            new_ks     = bytes(e ^ p for e, p in zip(tail_enc, known_tail))

            log.info(
                "Auto-extending keystream by %dB using known PEM footer "
                "and saving updated keystream.bin.", extra
            )
            keystream = keystream + new_ks
            with open(ks_path, "wb") as _f:
                _f.write(keystream)

        return bytes(enc[i] ^ keystream[i] for i in range(len(enc)))

    # ── Parse decrypted fields ────────────────────────────────────────────────
    ica_der  = decrypt("ica")          # Eureka Gen1 ICA cert (DER)

    # Sanity-check the keystream by verifying the ICA decrypts to the known cert.
    # If this fails, remotetogo has rotated their encryption key and keystream.bin
    # must be regenerated (capture a fresh pk.pem via Frida and re-run cert_fetch.py).
    known_ica_path = os.path.join(_here, "data", "intermediate.der")
    if os.path.exists(known_ica_path):
        with open(known_ica_path, "rb") as f:
            known_ica_der = f.read()
        if ica_der != known_ica_der:
            raise RuntimeError(
                "Keystream validation failed: decrypted 'ica' does not match intermediate.der. "
                "The API encryption key has likely rotated. "
                "Capture a fresh pk.pem via Frida TLS hook and re-run cert_fetch.py "
                "to regenerate keystream.bin."
            )
        log.debug("Keystream validated against intermediate.der")

    cpu_der  = decrypt("cpu")          # Google-signed device cert (DER)
    pub_der  = decrypt("pub")          # TLS cert (DER)
    pri_pem  = decrypt_pri("pri")       # TLS private key (PEM text, decrypted)
    sig256   = decrypt("sha256")       # pre-computed SHA-256 signature (raw bytes)
    sig1     = decrypt("sha1")         # pre-computed SHA-1   signature (raw bytes)

    # Quick sanity checks
    for name, der in [("cpu", cpu_der), ("pub", pub_der), ("ica", ica_der)]:
        if der[:2] != b"\x30\x82":
            raise RuntimeError(f"Decrypted {name} does not look like DER (got {der[:4].hex()})")
    if not pri_pem.startswith(b"-----BEGIN"):
        raise RuntimeError(f"Decrypted pri does not look like PEM (got {pri_pem[:16]})")
    if b"-----END PRIVATE KEY-----" not in pri_pem:
        log.warning(
            "Decrypted pri is missing the PEM end marker — keystream may be too short. "
            "Install keystream.bin to fix this."
        )
    log.debug("All decrypted fields pass DER/PEM sanity checks")

    paths = {
        "cert":         os.path.join(certs_dir, "tls.pem"),
        "key":          os.path.join(certs_dir, "pk.pem"),
        "auth_crt":     os.path.join(certs_dir, "auth.pem"),
        "intermediate": os.path.join(certs_dir, "intermediate.pem"),
        "sig_sha256":   os.path.join(certs_dir, "sig_sha256.bin"),
        "sig_sha1":     os.path.join(certs_dir, "sig_sha1.bin"),
        "not_before":   data["nb"],
        "not_after":    data["na"],
    }

    with open(paths["cert"], "wb") as f:
        f.write(_der_to_pem_cert(pub_der))

    with open(paths["key"], "wb") as f:
        # pri decrypts to PEM text; truncate at the PEM end marker to discard
        # any residual XOR-padding bytes that follow the actual key data.
        end_marker = b"-----END PRIVATE KEY-----"
        idx = pri_pem.find(end_marker)
        if idx != -1:
            f.write(pri_pem[:idx + len(end_marker)] + b"\n")
        else:
            # Keystream too short — save what we have stripped of null padding
            log.warning("PEM end marker not found in decrypted pri; saving truncated key.")
            f.write(pri_pem.rstrip(b"\x00"))

    with open(paths["auth_crt"], "wb") as f:
        f.write(_der_to_pem_cert(cpu_der))

    with open(paths["intermediate"], "wb") as f:
        f.write(_der_to_pem_cert(ica_der))

    with open(paths["sig_sha256"], "wb") as f:
        f.write(sig256)
    with open(paths["sig_sha1"], "wb") as f:
        f.write(sig1)

    # Save metadata for cache validation
    meta = {"not_before": data["nb"], "not_after": data["na"],
            "fetched_at": int(time.time())}
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    # Log cert info
    tls_cert = x509.load_der_x509_certificate(pub_der)
    auth_cert = x509.load_der_x509_certificate(cpu_der)
    log.info("Certificates saved to %s", certs_dir)
    log.info("  TLS cert  CN=%s  valid %s → %s",
             tls_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
             time.strftime("%Y-%m-%d", time.gmtime(data["nb"])),
             time.strftime("%Y-%m-%d", time.gmtime(data["na"])))
    log.info("  Auth cert CN=%s",
             auth_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value)

    return paths


def generate_keystream(pk_pem_path: str, ks_out_path: str | None = None) -> bytes:
    """Regenerate ``keystream.bin`` from a known-plaintext private key PEM.

    This performs a single fresh API call, XORs the encrypted ``pri`` field
    with the provided plaintext PEM, and writes the result to *ks_out_path*
    (defaults to ``keystream.bin`` next to this script).

    Use this when:
      - ``keystream.bin`` does not exist yet
      - The API has rotated its encryption key (ICA sanity check fails)
      - The key overshoot exceeds the 26-byte PEM footer guard

    Steps to obtain the plaintext ``pk.pem``:
      1. Run the Frida TLS hook (``utils/hook_cert_dump.js``) against the
         remotetogo app while it fetches certificates.
      2. Save the captured private key as ``pk.pem`` (PKCS#8 PEM format).
      3. Run:  ``python cert_fetch.py --gen-keystream pk.pem``
    """
    _here = os.path.dirname(os.path.abspath(__file__))
    if ks_out_path is None:
        ks_out_path = os.path.join(_here, "data", "keystream.bin")

    # Load known-plaintext PEM (strip trailing garbage / binary junk after the
    # end marker, as seen in certs/pk.pem captured via Frida).
    with open(pk_pem_path, "rb") as f:
        raw = f.read()
    end_marker = b"-----END PRIVATE KEY-----"
    idx = raw.find(end_marker)
    if idx == -1:
        raise ValueError(f"{pk_pem_path} does not contain a PKCS#8 PEM end marker.")
    plaintext = raw[: idx + len(end_marker)] + b"\n"

    # Fetch a fresh encrypted pri from the API.
    url = _api_url()
    log.info("Fetching API for keystream generation...")
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        raise RuntimeError(f"API request failed: {exc}") from exc

    def b64(field: str) -> bytes:
        raw_b64 = data[field]
        padding = (4 - len(raw_b64) % 4) % 4
        return base64.b64decode(raw_b64 + "=" * padding)

    enc_pri = b64("pri")

    if len(enc_pri) != len(plaintext):
        raise RuntimeError(
            f"Length mismatch: API encrypted pri is {len(enc_pri)}B but "
            f"'{pk_pem_path}' is {len(plaintext)}B. "
            "Make sure pk.pem was captured during the same key window as this API call."
        )

    keystream = bytes(e ^ p for e, p in zip(enc_pri, plaintext))

    with open(ks_out_path, "wb") as f:
        f.write(keystream)

    log.info("keystream.bin written (%dB) → %s", len(keystream), ks_out_path)
    return keystream


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)s [%(levelname)s] %(message)s",
                        datefmt="%H:%M:%S")
    script_dir = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(description="Certificate fetcher / keystream tool")
    parser.add_argument("--gen-keystream", metavar="PK_PEM",
                        help="Regenerate keystream.bin from a known-plaintext pk.pem")
    parser.add_argument("--ks-out", metavar="PATH",
                        help="Output path for keystream.bin (default: ./data/keystream.bin)")
    args = parser.parse_args()

    if args.gen_keystream:
        ks = generate_keystream(args.gen_keystream, args.ks_out)
        print(f"keystream.bin regenerated ({len(ks)}B)")
    else:
        result = fetch_certs(os.path.join(script_dir, ".cache", "certs"), force=True)
        print("\nFetched:")
        for k, v in result.items():
            print(f"  {k}: {v}")
