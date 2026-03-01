"""
mDNS Advertiser - Advertise as a Chromecast device on the local network.

This uses zeroconf to register a _googlecast._tcp service so that
Cast senders (Chrome, Google Home, etc.) can discover this receiver.
"""

import socket
import subprocess
import sys
import uuid
import hashlib
import logging
import time

from zeroconf import Zeroconf, ServiceInfo

log = logging.getLogger("mDNS")


class CastAdvertiser:
    """Advertise a Chromecast-compatible device via mDNS."""

    def __init__(self, friendly_name="Hiiragi Cast", port=8009, device_model="Eureka Dongle"):
        self.friendly_name = friendly_name
        self.port = port
        self.device_model = device_model
        self.zeroconf = None
        self.service_info = None

        # Generate a unique device ID (UUID-formatted, as Chrome requires)
        raw = hashlib.md5(
            (friendly_name + str(uuid.getnode())).encode()
        ).hexdigest()  # 32 lowercase hex chars
        self.device_id = (
            f"{raw[0:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:32]}"
        )  # e.g. e1c2752a-f23a-1b0b-0c28-90694a625281

        self._avahi_was_running = False

    def _get_local_ip(self):
        """Get the local IP address."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    # ------------------------------------------------------------------
    # avahi helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _avahi_running() -> bool:
        """Return True if avahi-daemon is currently active."""
        if not sys.platform.startswith("linux"):
            return False
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "avahi-daemon"],
                capture_output=True, text=True
            )
            return result.stdout.strip() == "active"
        except FileNotFoundError:
            return False

    @staticmethod
    def _avahi_set(active: bool):
        """Start or stop avahi-daemon (and its socket unit) via systemctl."""
        action = "start" if active else "stop"
        try:
            subprocess.run(
                ["sudo", "-n", "systemctl", action,
                 "avahi-daemon.socket", "avahi-daemon.service"],
                check=True, capture_output=True
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"Could not {action} avahi-daemon (needs passwordless sudo for systemctl):\n"
                + exc.stderr.decode(errors="replace").strip()
            ) from exc

    # ------------------------------------------------------------------

    def start(self):
        """Register the mDNS service."""
        local_ip = self._get_local_ip()
        log.info("Local IP: %s", local_ip)

        # On Linux, avahi-daemon owns port 5353 and blocks zeroconf.
        # Stop it temporarily so we can bind the multicast socket.
        if sys.platform.startswith("linux") and self._avahi_running():
            log.info("mDNS: stopping avahi-daemon so zeroconf can bind port 5353")
            try:
                self._avahi_set(active=False)
                self._avahi_was_running = True
                time.sleep(0.5)   # give the kernel a moment to release the socket
                log.info("mDNS: avahi-daemon stopped")
            except RuntimeError as exc:
                log.warning("mDNS: %s", exc)
                log.warning("mDNS: continuing anyway — discovery may not work")

        # Chromecast mDNS TXT record properties
        # Reference: https://developers.google.com/cast/docs/developers
        # id must be UUID-formatted lowercase (Chrome ignores non-UUID ids)
        # rm/rs must be b"" not omitted — use bytes so zeroconf keeps them
        node_id = self.device_id.replace("-", "")  # 32-char hex, no dashes
        properties = {
            b"id": self.device_id.encode(),          # UUID format, lowercase
            b"cd": node_id[:8].encode(),
            b"rm": b"",
            b"ve": b"05",
            b"md": self.device_model.encode(),
            b"ic": b"/setup/icon.png",
            b"fn": self.friendly_name.encode(),
            b"ca": b"4101",
            b"st": b"0",
            b"bs": b"FA8FCA5D4C32",  # realistic placeholder
            b"nf": b"1",
            b"rs": b"",
        }

        hostname = self.friendly_name.replace(" ", "-") + ".local."

        self.service_info = ServiceInfo(
            "_googlecast._tcp.local.",
            f"Chromecast-{node_id[:8]}._googlecast._tcp.local.",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=properties,
            server=hostname,
        )

        self.zeroconf = Zeroconf(interfaces=[local_ip])
        self.zeroconf.register_service(self.service_info, allow_name_change=True)

        log.info("=" * 60)
        log.info("mDNS: Registered as '%s' on %s:%d", self.friendly_name, local_ip, self.port)
        log.info("mDNS: Device ID: %s", self.device_id.upper())
        log.info("mDNS: Service: _googlecast._tcp")
        log.info("=" * 60)

    def stop(self):
        """Unregister the mDNS service and restore avahi-daemon if we stopped it."""
        if self.zeroconf and self.service_info:
            self.zeroconf.unregister_service(self.service_info)
            self.zeroconf.close()
            log.info("mDNS service unregistered")

        if self._avahi_was_running:
            log.info("mDNS: restoring avahi-daemon")
            try:
                self._avahi_set(active=True)
                self._avahi_was_running = False
                log.info("mDNS: avahi-daemon restarted")
            except RuntimeError as exc:
                log.warning("mDNS: could not restart avahi-daemon: %s", exc)


def main():
    """Standalone mDNS test."""
    logging.basicConfig(level=logging.INFO)
    adv = CastAdvertiser("TestCast")
    adv.start()
    try:
        log.info("Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        adv.stop()


if __name__ == "__main__":
    main()
