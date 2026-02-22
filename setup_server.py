"""
Chromecast Setup HTTP Server (port 8008)

The Google Home app (Android/iOS) validates discovered Cast devices by doing
an HTTP GET to port 8008 before showing them in the device list.  Without a
response here the phone silently skips the device even when mDNS is working.

Endpoints implemented:
  GET /setup/eureka_info          – device capabilities JSON (required)
  GET /ssdp/device-desc.xml       – optional UPnP description
  GET /setup/icon.png             – optional 55x55 PNG icon (returns 204)
"""

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

log = logging.getLogger("SetupServer")


class _SetupHandler(BaseHTTPRequestHandler):
    # Injected by CastSetupServer.start()
    device_info: dict = {}

    def log_message(self, fmt, *args):
        log.debug("Setup HTTP %s %s", self.address_string(), fmt % args)

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/setup/eureka_info":
            self._send_json(self.device_info)

        elif path == "/ssdp/device-desc.xml":
            d = self.device_info
            xml = (
                '<?xml version="1.0"?>'
                '<root xmlns="urn:schemas-upnp-org:device-1-0">'
                "<specVersion><major>1</major><minor>0</minor></specVersion>"
                "<device>"
                f"<deviceType>urn:dial-multiscreen-org:device:dial:1</deviceType>"
                f"<friendlyName>{d.get('name','CastTest')}</friendlyName>"
                f"<manufacturer>Google Inc.</manufacturer>"
                f"<modelName>{d.get('model_name','Chromecast')}</modelName>"
                f"<UDN>uuid:{d.get('uuid','')}</UDN>"
                "</device></root>"
            )
            body = xml.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path in ("/setup/icon.png", "/setup/icon.jpg"):
            # Return empty 204 — enough to satisfy the app
            self.send_response(204)
            self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()


class CastSetupServer:
    """HTTP server on port 8008 that answers Google Home device validation."""

    def __init__(self, friendly_name, device_id, port=8008, cast_port=8009,
                 device_model="Chromecast"):
        import uuid as _uuid
        self.port = port
        self._server = None
        self._thread = None

        _SetupHandler.device_info = {
            # Core fields checked by Google Home app
            "bssid":            "11:22:33:44:55:66",
            "build_version":    "1.56.330094",
            "cast_build_revision": "1.56.330094",
            "connected":        True,
            "ethernet_connected": False,
            "has_update":       False,
            "hotspot_bssid":    "00:00:00:00:00:00",
            "ip_address":       "",           # not required
            "locale":           "en",
            "location":         {},
            "mac_address":      "11:22:33:44:55:66",
            "model_name":       device_model,
            "name":             friendly_name,
            "noise_level":      -90,
            "opencast_pin_code":"",
            "opt_in":           {"crash": False, "opencast": False, "stats": False},
            "public_key":       "",
            "release_track":    "stable-channel",
            "setup_state":      4,          # 4 = setup complete
            "setup_stats":      {"historically_succeeded": True,
                                 "num_failures": 0, "num_success": 1},
            "signal_level":     -40,
            "ssdp_udn":         device_id.lower(),
            "ssid":             "",
            "time_format":      1,
            "timezone":         "UTC",
            "tos_accepted":     True,
            "uma_client_id":    device_id.lower(),
            "uptime":           3600.0,
            "uuid":             device_id.lower(),
            "version":          12,
            "wpa_configured":   True,
            "wpa_state":        10,
            "device_info": {
                "manufacturer":  "Google Inc.",
                "product_name":  "Chromecast",
                "ssdp_udn":      device_id.lower(),
            },
        }

    def start(self):
        server = HTTPServer(("0.0.0.0", self.port), _SetupHandler)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever,
                                        daemon=True, name="SetupServer")
        self._thread.start()
        log.info("Setup HTTP server listening on port %d", self.port)

    def stop(self):
        if self._server:
            self._server.shutdown()
