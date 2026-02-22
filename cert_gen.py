import time
from datetime import datetime
from OpenSSL import crypto


def generate_tls_cert(private_key_path, output_cert_path):
    """Generates a new TLS certificate using the provided private key."""
    # Load the existing private key
    with open(private_key_path, "rb") as f:
        key_data = f.read()
        if b"-----BEGIN" in key_data:
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)
        else:
            pkey = crypto.load_privatekey(crypto.FILETYPE_ASN1, key_data)

    # Set validity dates dynamically
    TWO_DAYS = 2 * 24 * 60 * 60
    BASE_DATE = 1692057600  # Aug 15, 2023

    now = int(time.time())
    index = (now - BASE_DATE) // TWO_DAYS
    not_before_ts = BASE_DATE + index * TWO_DAYS
    not_after_ts  = not_before_ts + TWO_DAYS

    dt_not_before = datetime.utcfromtimestamp(not_before_ts)
    dt_not_after  = datetime.utcfromtimestamp(not_after_ts)

    # Build the certificate
    cert = crypto.X509()
    cert.set_version(2)  # X.509 v3 (0-indexed)
    cert.set_serial_number(36014438)  # 0x2258966

    # Subject / Issuer — same DN as the original cert
    subj = cert.get_subject()
    subj.emailAddress = "support-as@ionitech.cn"
    subj.C  = "CN"
    subj.ST = "CQ"
    subj.L  = "CQ"
    subj.O  = "IONITECH"
    subj.OU = "IONITECH"
    subj.CN = "AIRSCREEN"
    cert.set_issuer(cert.get_subject())

    cert.set_pubkey(pkey)

    # Passing a 15-char YYYYMMDDHHMMSSZ string makes OpenSSL encode as
    # GeneralizedTime (tag 0x18) instead of the default UTCTime (tag 0x17).
    # This matches the original cert's encoding exactly.
    cert.set_notBefore(dt_not_before.strftime("%Y%m%d%H%M%SZ").encode())
    cert.set_notAfter(dt_not_after.strftime("%Y%m%d%H%M%SZ").encode())

    cert.sign(pkey, "sha256")

    with open(output_cert_path, "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    return output_cert_path
