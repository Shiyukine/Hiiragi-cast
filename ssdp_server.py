"""
SSDP Server – UPnP/SSDP discovery for Chromecast-compatible devices.

Responds to M-SEARCH requests on the DIAL multicast group so that phones and
apps (Google Home, YouTube, etc.) can discover this receiver via UPnP in
addition to mDNS.

The DIAL (Discovery and Launch) protocol used by Chromecast relies on:
  - SSDP multicast 239.255.255.250:1900
  - Service type: urn:dial-multiscreen-org:service:dial:1
  - A LOCATION pointing to the UPnP device-desc.xml hosted on port 8008
"""

import socket
import struct
import threading
import logging
import time

log = logging.getLogger("SSDP")

SSDP_MULTICAST = "239.255.255.250"
SSDP_PORT = 1900

# Service types to announce / respond to
_ST_DIAL    = "urn:dial-multiscreen-org:service:dial:1"
_ST_ROOT    = "upnp:rootdevice"
_ST_ALL     = "ssdp:all"


class SSDPServer:
    """Minimal SSDP server that advertises a Chromecast-compatible DIAL device."""

    def __init__(self, friendly_name: str, local_ip: str,
                 http_port: int = 8008, device_uuid: str = ""):
        self.friendly_name = friendly_name
        self.local_ip = local_ip
        self.http_port = http_port
        # UUID in the form "uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        if not device_uuid.startswith("uuid:"):
            device_uuid = "uuid:" + device_uuid
        self.device_uuid = device_uuid
        self._running = False
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ #
    #  Message builders                                                    #
    # ------------------------------------------------------------------ #

    def _location(self) -> str:
        return f"http://{self.local_ip}:{self.http_port}/ssdp/device-desc.xml"

    def _usn(self, st: str) -> str:
        if st == self.device_uuid:
            return self.device_uuid
        return f"{self.device_uuid}::{st}"

    def _msearch_response(self, st: str) -> bytes:
        """Build an HTTP/1.1 200 OK response for an M-SEARCH request."""
        lines = [
            "HTTP/1.1 200 OK",
            f"LOCATION: {self._location()}",
            f"ST: {st}",
            f"USN: {self._usn(st)}",
            "EXT:",
            "CACHE-CONTROL: max-age=1800",
            'OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01',
            f"01-NLS: {self.device_uuid}",
            "SERVER: Linux/3.8 UPnP/1.0 Chromium/56.0.2924.41",
            "",
            "",
        ]
        return "\r\n".join(lines).encode()

    def _notify_msg(self, nts: str, st: str) -> bytes:
        """Build a SSDP NOTIFY message (alive or byebye)."""
        if nts == "ssdp:alive":
            lines = [
                "NOTIFY * HTTP/1.1",
                f"HOST: {SSDP_MULTICAST}:{SSDP_PORT}",
                "CACHE-CONTROL: max-age=1800",
                f"LOCATION: {self._location()}",
                f"NT: {st}",
                f"USN: {self._usn(st)}",
                f"NTS: {nts}",
                "SERVER: Linux/3.8 UPnP/1.0 Chromium/56.0.2924.41",
                "",
                "",
            ]
        else:  # ssdp:byebye
            lines = [
                "NOTIFY * HTTP/1.1",
                f"HOST: {SSDP_MULTICAST}:{SSDP_PORT}",
                f"NT: {st}",
                f"USN: {self._usn(st)}",
                f"NTS: {nts}",
                "",
                "",
            ]
        return "\r\n".join(lines).encode()

    # ------------------------------------------------------------------ #
    #  Internals                                                           #
    # ------------------------------------------------------------------ #

    def _broadcast(self, sock: socket.socket, nts: str):
        """Send alive/byebye NOTIFYs for all service types."""
        for st in [_ST_ROOT, self.device_uuid, _ST_DIAL]:
            try:
                sock.sendto(self._notify_msg(nts, st), (SSDP_MULTICAST, SSDP_PORT))
            except Exception as exc:
                log.debug("SSDP NOTIFY error: %s", exc)

    def _run(self):
        # Create UDP socket bound to SSDP port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            # SO_REUSEPORT not available on Windows
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass
        sock.bind(("", SSDP_PORT))

        # Join the SSDP multicast group on our local interface
        mreq = struct.pack("4s4s",
                           socket.inet_aton(SSDP_MULTICAST),
                           socket.inet_aton(self.local_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1.0)

        # Announce ourselves
        self._broadcast(sock, "ssdp:alive")
        log.info("SSDP: Listening on %s:%d (interface %s)",
                 SSDP_MULTICAST, SSDP_PORT, self.local_ip)

        last_alive = time.time()

        while self._running:
            # Re-announce every 10 minutes so clients keep our entry fresh
            if time.time() - last_alive > 600:
                self._broadcast(sock, "ssdp:alive")
                last_alive = time.time()

            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except Exception as exc:
                log.debug("SSDP recv error: %s", exc)
                continue

            try:
                msg = data.decode("utf-8", errors="ignore")
                if not msg.startswith("M-SEARCH"):
                    continue

                # Extract the ST header
                st_req = ""
                for line in msg.splitlines():
                    if line.upper().startswith("ST:"):
                        st_req = line[3:].strip()
                        break

                # Respond to DIAL, root-device, and wildcard searches
                if st_req in (_ST_DIAL, _ST_ROOT, _ST_ALL, ""):
                    reply_st = _ST_DIAL if st_req != _ST_ROOT else _ST_ROOT
                    log.debug("SSDP: M-SEARCH from %s (ST=%s) → responding", addr, st_req)
                    sock.sendto(self._msearch_response(reply_st), addr)
            except Exception as exc:
                log.debug("SSDP dispatch error: %s", exc)

        # Graceful shutdown — announce byebye
        self._broadcast(sock, "ssdp:byebye")
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
        except Exception:
            pass
        sock.close()
        log.info("SSDP: Stopped")

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def start(self):
        """Start the SSDP listener in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="SSDP")
        self._thread.start()
        log.info("SSDP: Started for '%s' at %s", self.friendly_name, self.local_ip)

    def stop(self):
        """Signal the background thread to stop and wait for it."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        log.info("SSDP: Stopped for '%s'", self.friendly_name)
