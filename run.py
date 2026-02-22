"""
Cast V2 Test Runner
Starts both the mDNS advertiser and the Cast V2 TLS receiver.

Usage:
    python run.py                              # Use default cert/key paths
    python run.py --name "My Chromecast"       # Custom device name
    python run.py --cert path/to/cert.pem --key path/to/key.pem
    python run.py --no-mdns                    # Skip mDNS (manual testing only)
"""

import argparse
import logging
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from receiver import CastReceiver
from mdns_advertiser import CastAdvertiser
from cert_gen import generate_tls_cert
from media_bridge import MediaBridge
from setup_server import CastSetupServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("CastTest")


def main():
    parser = argparse.ArgumentParser(
        description="Cast V2 Receiver Test - Chromecast Authentication Test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py
  python run.py --name "Living Room TV" --port 8009
  python run.py --cert ../AIRSCREEN.crt --key ../pk.pem --no-mdns

Testing:
  1. Run this script on your PC
  2. Open Chrome and look for Cast devices (three-dot menu > Cast)
  3. Your device should appear as the name you specified
  4. If authentication succeeds, you'll see AUTH/CONNECT/HEARTBEAT in logs
  5. You can also test with: pychromecast or catt CLI tools
        """,
    )
    parser.add_argument("--cert", default="./tls.pem",
                        help="TLS certificate (default: ./tls.pem)")
    parser.add_argument("--key", default="./pk.pem",
                        help="TLS private key (default: ./pk.pem)")
    parser.add_argument("--generate-cert", action="store_true",
                        help="Generate a new TLS certificate dynamically using the provided key")
    parser.add_argument("--intermediate", default="./intermediate.pem",
                        help="Intermediate CA certificates (default: ./intermediate.pem)")
    parser.add_argument("--auth-crt", default="./auth.pem",
                        help="Google Device Certificate for auth bypass (default: ./auth.pem)")
    parser.add_argument("--signatures", default="../signatures.txt",
                        help="Pre-computed signatures for auth bypass (default: ../signatures.txt)")
    parser.add_argument("--port", type=int, default=8009,
                        help="Port number (default: 8009)")
    parser.add_argument("--name", default="CastTest",
                        help="Device friendly name (default: CastTest)")
    parser.add_argument("--no-mdns", action="store_true",
                        help="Don't advertise via mDNS")
    parser.add_argument("--electron", action="store_true",
                        help="Start the Electron player and stream media events to it")
    parser.add_argument("--bridge-port", type=int, default=9000,
                        help="WebSocket port for Electron bridge (default: 9000)")

    args = parser.parse_args()

    # Resolve paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cert_path = os.path.join(script_dir, args.cert) if not os.path.isabs(args.cert) else args.cert
    key_path = os.path.join(script_dir, args.key) if not os.path.isabs(args.key) else args.key
    int_path = None
    if args.intermediate:
        int_path = os.path.join(script_dir, args.intermediate) if not os.path.isabs(args.intermediate) else args.intermediate
    auth_crt_path = None
    if args.auth_crt:
        auth_crt_path = os.path.join(script_dir, args.auth_crt) if not os.path.isabs(args.auth_crt) else args.auth_crt
    signatures_path = None
    if args.signatures:
        signatures_path = os.path.join(script_dir, args.signatures) if not os.path.isabs(args.signatures) else args.signatures

    # Verify files exist
    if not os.path.exists(key_path):
        log.error("TLS Private key not found: %s", key_path)
        sys.exit(1)

    if args.generate_cert:
        log.info("Generating new TLS certificate dynamically...")
        cert_path = generate_tls_cert(key_path, cert_path)
    elif not os.path.exists(cert_path):
        log.error("TLS Certificate not found: %s", cert_path)
        sys.exit(1)

    log.info("=" * 60)
    log.info("  CHROMECAST RECEIVER AUTHENTICATION TEST")
    log.info("=" * 60)
    log.info("  TLS Certificate : %s", cert_path)
    log.info("  TLS Private Key : %s", key_path)
    if auth_crt_path and os.path.exists(auth_crt_path):
        log.info("  Auth Cert       : %s", auth_crt_path)
    if signatures_path and os.path.exists(signatures_path):
        log.info("  Signatures      : %s", signatures_path)
    log.info("  Port            : %d", args.port)
    log.info("  Device Name     : %s", args.name)
    log.info("  mDNS            : %s", "disabled" if args.no_mdns else "enabled")
    log.info("  Electron bridge : %s", f"ws://localhost:{args.bridge_port}" if args.electron else "disabled")
    log.info("=" * 60)

    # Start media bridge (optional Electron player)
    bridge = None
    if args.electron:
        bridge = MediaBridge(port=args.bridge_port)
        bridge.start()
        # Launch the Electron app
        import subprocess, shutil
        electron_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "electron-player")
        if os.path.isdir(electron_dir):
            log.info("Launching Electron player from %s", electron_dir)
            # On Windows npm/npx are .cmd batch files and cannot be invoked as
            # plain executables — shell=True is required.
            subprocess.Popen("npm run start",
                             cwd=electron_dir,
                             shell=True,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        else:
            log.warning("Electron player directory not found: %s", electron_dir)
            log.warning("Run: cd electron-player && npm install")

    # On Windows, ensure the firewall allows mDNS (UDP 5353) and the Cast port.
    # This runs silently — no-op on non-Windows or if rules already exist.
    if sys.platform == "win32" and not args.no_mdns:
        import subprocess as _sp
        any_failed = False
        for _rule, _proto, _port in [
            ("HiiragiCast-mDNS",   "UDP", "5353"),
            ("HiiragiCast-Setup",  "TCP", "8008"),
            ("HiiragiCast-Cast",   "TCP", str(args.port)),
        ]:
            r = _sp.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={_rule}", "dir=in", "action=allow",
                 f"protocol={_proto}", f"localport={_port}"],
                capture_output=True, check=False,
            )
            if r.returncode != 0:
                any_failed = True
        if any_failed:
            log.warning("Could not add Windows Firewall rules — run once as Administrator"
                        " so mDNS discovery works on all network profiles")

    # Start mDNS advertiser
    advertiser = None
    if not args.no_mdns:
        advertiser = CastAdvertiser(args.name, args.port)

        # Setup HTTP server on port 8008 (required by Google Home app on phones)
        setup_srv = CastSetupServer(
            friendly_name=args.name,
            device_id=advertiser.device_id,
            cast_port=args.port,
        )
        try:
            setup_srv.start()
        except Exception as e:
            log.warning("Setup HTTP server failed (non-fatal): %s", e)
            log.warning("Google Home app on phones may not find this device")

        try:
            advertiser.start()
        except Exception as e:
            log.warning("mDNS failed (non-fatal): %s", e)
            log.warning("You can still test by connecting directly to this IP:port")
            advertiser = None

    # Start receiver
    receiver = CastReceiver(
        cert_file=cert_path,
        key_file=key_path,
        peer_cert_file=int_path,
        port=args.port,
        auth_crt_file=auth_crt_path,
        signatures_file=signatures_path,
        media_bridge=bridge,
        friendly_name=args.name,
        device_id=advertiser.device_id if advertiser else None,
    )
    try:
        receiver.start()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log.error("Receiver error: %s", e)
    finally:
        if advertiser:
            advertiser.stop()
        log.info("Shutdown complete.")


if __name__ == "__main__":
    main()
