"""
Cast V2 Main
Starts both the mDNS advertiser and the Cast V2 TLS receiver.
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
from cert_fetch import fetch_certs
from media_bridge import MediaBridge
from setup_server import CastSetupServer
from ssdp_server import SSDPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("Hiiragi Cast")


def main():
    parser = argparse.ArgumentParser(
        description="Cast V2 Receiver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py --name "Living Room TV" --port 8009
  python main.py --cert ../AIRSCREEN.crt --key ../pk.pem --no-mdns

Testing:
  1. Run this script on your PC
  2. Open Chrome and look for Cast devices (three-dot menu > Cast)
  3. Your device should appear as the name you specified
  4. If authentication succeeds, you'll see AUTH/CONNECT/GET_STATUS in logs
        """,
    )
    parser.add_argument("--cert", default="./certs/tls.pem",
                        help="TLS certificate (default: ./certs/tls.pem)")
    parser.add_argument("--key", default="./certs/pk.pem",
                        help="TLS private key (default: ./certs/pk.pem)")
    parser.add_argument("--no-fetch-certs", action="store_true",
                        help="Don't fetch fresh certificates from the remotetogo API")
    parser.add_argument("--force-fetch", action="store_true",
                        help="Force re-fetch even if cached certs are still valid")
    parser.add_argument("--intermediate", default="./certs/intermediate.pem",
                        help="Intermediate CA certificates (default: ./certs/intermediate.pem)")
    parser.add_argument("--auth-crt", default="./certs/auth.pem",
                        help="Google Device Certificate for auth bypass (default: ./certs/auth.pem)")
    parser.add_argument("--signatures", default="./certs/sig_sha256.bin",
                        help="Pre-computed SHA-256 signature (default: ./certs/sig_sha256.bin)")
    parser.add_argument("--port", type=int, default=8009,
                        help="Port number (default: 8009)")
    parser.add_argument("--name", default="Hiiragi Cast",
                        help="Device friendly name (default: Hiiragi Cast)")
    parser.add_argument("--no-mdns", action="store_true",
                        help="Don't advertise via mDNS")
    parser.add_argument("--no-electron", action="store_true",
                        help="Don't start the Electron player and stream media events to it")
    parser.add_argument("--bridge-port", type=int, default=9000,
                        help="WebSocket port for Electron bridge (default: 9000)")
    parser.add_argument("--audio-device", default=None, metavar="DEVICE",
                        help="Audio output device: index number or name substring "
                             "(run with --list-audio-devices to see available devices)")
    parser.add_argument("--list-audio-devices", action="store_true",
                        help="Print available audio output devices and exit")

    args = parser.parse_args()

    if args.list_audio_devices:
        try:
            import sounddevice as _sd
            devices = _sd.query_devices()
            print("\nAvailable audio output devices:")
            print(f"  {'IDX':>4}  {'NAME'}")
            print("  " + "-" * 60)
            for i, d in enumerate(devices):
                if d['max_output_channels'] > 0:
                    marker = " <-- default" if i == _sd.default.device[1] else ""
                    print(f"  {i:>4}  {d['name']}{marker}")
            print()
        except ImportError:
            print("sounddevice is not installed — cannot list devices")
        sys.exit(0)

    # Resolve paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    certs_dir  = os.path.join(script_dir, "certs")

    def _abspath(p):
        return p if os.path.isabs(p) else os.path.join(script_dir, p)

    cert_path       = _abspath(args.cert)
    key_path        = _abspath(args.key)
    int_path        = _abspath(args.intermediate) if args.intermediate else None
    auth_crt_path   = _abspath(args.auth_crt)     if args.auth_crt     else None
    signatures_path = _abspath(args.signatures)   if args.signatures   else None

    # ── Fetch / refresh certificates ──────────────────────────────────────────
    # Auto-fetch when any required cert file is missing, or when explicitly asked.
    certs_missing = not os.path.exists(cert_path) or not os.path.exists(key_path)
    if not args.no_fetch_certs:
        try:
            fetched = fetch_certs(certs_dir, force=args.force_fetch)
            cert_path       = fetched["cert"]
            key_path        = fetched["key"]
            auth_crt_path   = fetched["auth_crt"]
            int_path        = fetched["intermediate"]
            signatures_path = fetched["sig_sha256"]
        except Exception as exc:
            log.error("Failed to fetch certificates: %s", exc)
            if certs_missing:
                sys.exit(1)
            log.warning("Falling back to existing certificates")

    # Verify key exists (cert is verified implicitly by TLS context creation)
    if not os.path.exists(key_path):
        log.error("TLS Private key not found: %s", key_path)
        sys.exit(1)
    if not os.path.exists(cert_path):
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
    log.info("  Electron bridge : %s", f"ws://localhost:{args.bridge_port}" if not args.no_electron else "disabled")
    log.info("=" * 60)

    # Start media bridge (optional Electron player)
    bridge = None
    electron_proc = None
    if not args.no_electron:
        bridge = MediaBridge(port=args.bridge_port)
        bridge.start()
        # Launch the Electron app
        import subprocess, shutil
        electron_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "electron-player")
        if os.path.isdir(electron_dir):
            log.info("Launching Electron player from %s", electron_dir)
            # CREATE_NO_WINDOW  — no console window shown
            # CREATE_NEW_PROCESS_GROUP — Ctrl+C does not propagate to Electron
            _flags = 0
            if sys.platform == "win32":
                _flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            electron_cmd = "npm run start"
            if sys.platform == "linux" or sys.platform == "linux2": # Linux
                electron_cmd = "npm run startFix"
            if sys.platform == "darwin": # macOS
                electron_cmd = "npm run startFixMac"
            electron_proc = subprocess.Popen(
                electron_cmd,
                cwd=electron_dir,
                shell=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=_flags,
            )
            log.info("Electron player launched (pid=%d)", electron_proc.pid)

            # When Electron closes, stop the Python server automatically.
            def _electron_watchdog(proc):
                proc.wait()   # blocks until npm/Electron process tree exits
                log.info("Electron player closed — stopping server")
                import signal as _sig, os as _os
                _os.kill(_os.getpid(), _sig.SIGINT)
            threading.Thread(target=_electron_watchdog, args=(electron_proc,),
                             daemon=True, name="ElectronWatchdog").start()
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
            ("HiiragiCast-SSDP",   "UDP", "1900"),
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
    ssdp_srv = None
    if not args.no_mdns:
        advertiser = CastAdvertiser(args.name, args.port)

        # Setup HTTP server on port 8008 (required by Google Home app on phones)
        _local_ip = advertiser._get_local_ip()
        setup_srv = CastSetupServer(
            friendly_name=args.name,
            device_id=advertiser.device_id,
            cast_port=args.port,
            local_ip=_local_ip,
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

        # Start SSDP (UPnP discovery — lets phones find the device on some networks)
        try:
            import socket as _sock
            _s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            _s.connect(("8.8.8.8", 80))
            _local_ip = _s.getsockname()[0]
            _s.close()
            _uuid = advertiser.device_id.lower() if advertiser else "00000000000000000000000000000000"
            ssdp_srv = SSDPServer(
                friendly_name=args.name,
                local_ip=_local_ip,
                http_port=8008,
                device_uuid=_uuid,
            )
            ssdp_srv.start()
        except Exception as e:
            log.warning("SSDP server failed (non-fatal): %s", e)
            ssdp_srv = None

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
        audio_device=args.audio_device,
    )
    try:
        receiver.start()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log.error("Receiver error: %s", e)
    finally:
        # Kill the Electron process tree before anything else.
        # taskkill /T kills npm + all its children (the actual Electron process).
        if electron_proc is not None:
            try:
                if sys.platform == "win32":
                    import subprocess as _sp
                    _sp.run(["taskkill", "/F", "/T", "/PID", str(electron_proc.pid)],
                            capture_output=True, check=False)
                else:
                    import signal as _sig
                    electron_proc.send_signal(_sig.SIGTERM)
                    electron_proc.wait(timeout=3)
            except Exception:
                pass
        if bridge:
            bridge.stop()
        if advertiser:
            advertiser.stop()
        if ssdp_srv:
            ssdp_srv.stop()
        log.info("Shutdown complete.")
        # Zeroconf (mDNS) starts non-daemon threads internally.  If they haven't
        # finished by now, Python's normal shutdown will block waiting for them —
        # and never reach the C-level console-mode restore, leaving the terminal
        # broken.  Marking every remaining non-daemon thread as daemon here lets
        # Python exit immediately while still running its own finaliser cleanly.
        import threading as _threading
        for _t in _threading.enumerate():
            if _t is not _threading.main_thread() and not _t.daemon:
                try:
                    _t.daemon = True
                except RuntimeError:
                    pass


if __name__ == "__main__":
    main()
