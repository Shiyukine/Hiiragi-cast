"""
mDNS Advertiser - Advertise as a Chromecast device on the local network.

This uses zeroconf to register a _googlecast._tcp service so that
Cast senders (Chrome, Google Home, etc.) can discover this receiver.
"""

import socket
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

        # Generate a unique device ID
        self.device_id = hashlib.md5(
            (friendly_name + str(uuid.getnode())).encode()
        ).hexdigest().upper()

    def _get_local_ip(self):
        """Get the local IP address."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()

    def start(self):
        """Register the mDNS service."""
        local_ip = self._get_local_ip()
        log.info("Local IP: %s", local_ip)

        # Chromecast mDNS TXT record properties
        # Reference: https://developers.google.com/cast/docs/developers
        properties = {
            "id": self.device_id.lower(),  # must be lowercase
            "cd": self.device_id[:8].lower(),
            "rm": "",
            "ve": "05",  # version
            "md": self.device_model,
            "ic": "/setup/icon.png",
            "fn": self.friendly_name,
            "ca": "4101",   # capabilities: video + audio
            "st": "0",  # idle status
            "bs": "000000000000",
            "nf": "1",
            "rs": "",
        }

        hostname = self.friendly_name.replace(" ", "-") + ".local."

        self.service_info = ServiceInfo(
            "_googlecast._tcp.local.",
            f"Chromecast-{self.device_id[:8]}._googlecast._tcp.local.",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=properties,
            server=hostname,
        )

        self.zeroconf = Zeroconf(interfaces=[local_ip])
        self.zeroconf.register_service(self.service_info, allow_name_change=True)

        log.info("=" * 60)
        log.info("mDNS: Registered as '%s' on %s:%d", self.friendly_name, local_ip, self.port)
        log.info("mDNS: Device ID: %s", self.device_id)
        log.info("mDNS: Service: _googlecast._tcp")
        log.info("=" * 60)

    def stop(self):
        """Unregister the mDNS service."""
        if self.zeroconf and self.service_info:
            self.zeroconf.unregister_service(self.service_info)
            self.zeroconf.close()
            log.info("mDNS service unregistered")


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
