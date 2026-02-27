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

import base64
import hashlib
import json
import logging
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

log = logging.getLogger("SetupServer")


# ---------------------------------------------------------------------------
# Minimal WebSocket frame helpers (RFC 6455 — text frames only)
# ---------------------------------------------------------------------------

def _ws_recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("WebSocket connection closed")
        buf += chunk
    return buf


def _ws_read_frame(sock):
    """Read one WebSocket frame. Returns (opcode, payload_bytes)."""
    h = _ws_recv_exact(sock, 2)
    opcode = h[0] & 0x0F
    masked = (h[1] >> 7) & 1
    length = h[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", _ws_recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _ws_recv_exact(sock, 8))[0]
    mask = _ws_recv_exact(sock, 4) if masked else b""
    payload = bytearray(_ws_recv_exact(sock, length))
    if masked:
        for i in range(length):
            payload[i] ^= mask[i % 4]
    return opcode, bytes(payload)


def _ws_write_text(sock, text: str):
    """Send a single unmasked text frame."""
    data = text.encode("utf-8")
    length = len(data)
    if length < 126:
        header = bytes([0x81, length])
    elif length < 65536:
        header = bytes([0x81, 126]) + struct.pack(">H", length)
    else:
        header = bytes([0x81, 127]) + struct.pack(">Q", length)
    sock.sendall(header + data)


# ---------------------------------------------------------------------------
# Cast IPC bridge  (ws://localhost:8008/v2/ipc)
# ---------------------------------------------------------------------------

# The Cast IPC protocol wraps every message as:
#   {"namespace": "<ns>", "senderId": "<id>", "data": "<json-string>"}
# System events (connected/ready/senderconnected/etc.) use the system namespace.
_IPC_NS_SYSTEM = "urn:x-cast:com.google.cast.system"
_IPC_SYSTEM_SENDER = "SystemSender"


class CastIpcBridge:
    """Manages the ws://localhost:8008/v2/ipc WebSocket connection.

    The Cast SDK running inside the Electron webview connects here immediately
    after the receiver page loads.  We proxy Cast V2 messages to/from the SDK
    via this channel.

    Protocol (recovered from cast_receiver_framework.js — IpcChannel.Qk / .send):
      Every wire frame is a JSON text:
        {"namespace": "<ns>", "senderId": "<id>", "data": "<json-encoded-string>"}
      System events go to namespace "urn:x-cast:com.google.cast.system".
      On WebSocket open the SDK synthesises an "opened" event internally, which
      causes CastReceiverManager to call sf() and send its {"type":"ready", ...}
      system message to us.  We then reply with the platform "ready" (app launch
      info), which completes the handshake and fires CastReceiverManager.ready.
    """

    def __init__(self):
        self._sock = None
        self._lock = threading.Lock()
        self.on_message: Optional[Callable] = None    # callable(namespace, sender_id, data_str)
        self.on_sdk_ready: Optional[Callable] = None  # callable()
        self.on_sdk_disconnected: Optional[Callable] = None  # callable()
        # Must be populated by receiver.py before the SDK connects (or very
        # shortly after — the SDK waits for our reply before becoming "ready").
        self.launch_info: dict = {}  # keys: applicationId, applicationName, sessionId, ...
        # Namespaces the SDK has registered (populated from its ready message)
        self.active_namespaces: list = []
        # Heartbeat state (set up when SDK sends startheartbeat)
        self._hb_stop = threading.Event()
        self._hb_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    @property
    def is_connected(self) -> bool:
        return self._sock is not None

    def send_message(self, namespace: str, sender_id: str, data: str):
        """Forward a Cast V2 payload (JSON string) to the SDK on *namespace*."""
        self._send(json.dumps({
            "namespace": namespace,
            "senderId": sender_id,
            "data": data,
        }))

    def send_sender_connected(self, sender_id: str, user_agent: str = "Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 CrKey/1.56.467165"):
        """Notify the SDK that a new Cast sender connected."""
        self._sys_send({
            "type": "senderconnected",
            "senderId": sender_id,
            "userAgent": user_agent,
        })

    def send_sender_disconnected(self, sender_id: str,
                                 reason: str = "requested_by_sender"):
        """Notify the SDK that a Cast sender disconnected."""
        self._sys_send({
            "type": "senderdisconnected",
            "senderId": sender_id,
            "reason": reason,
        })

    def disconnect(self):
        """Close the IPC connection (e.g. when the app is stopped)."""
        self._stop_heartbeat()
        with self._lock:
            sock = self._sock
            self._sock = None
        if sock:
            try:
                sock.sendall(bytes([0x88, 0x00]))  # WS close frame
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    #  Internal — called from _SetupHandler WS thread                     #
    # ------------------------------------------------------------------ #

    def _sys_send(self, data_dict: dict):
        """Send a system-namespace message to the SDK."""
        self._send(json.dumps({
            "namespace": _IPC_NS_SYSTEM,
            "senderId": _IPC_SYSTEM_SENDER,
            "data": json.dumps(data_dict),
        }))

    def _start_heartbeat(self, interval: float):
        """Start a background thread that pings the SDK every *interval* seconds."""
        self._stop_heartbeat()  # cancel any existing one
        self._hb_stop.clear()
        def _loop():
            while not self._hb_stop.wait(timeout=interval):
                if not self.is_connected:
                    break
                self._sys_send({"type": "ping"})
                log.debug("[IPC] Heartbeat ping sent")
        self._hb_thread = threading.Thread(target=_loop, daemon=True, name="IPC-heartbeat")
        self._hb_thread.start()
        log.debug("[IPC] Heartbeat started (interval=%.0fs)", interval)

    def _stop_heartbeat(self):
        """Cancel the heartbeat thread if running."""
        self._hb_stop.set()
        if self._hb_thread and self._hb_thread.is_alive():
            self._hb_thread.join(timeout=2)
        self._hb_thread = None

    def _send(self, text: str):
        with self._lock:
            sock = self._sock
        if not sock:
            log.debug("[IPC] Cannot send — no SDK connected")
            return
        try:
            _ws_write_text(sock, text)
        except Exception as exc:
            log.warning("[IPC] Send failed: %s", exc)
            with self._lock:
                if self._sock is sock:
                    self._sock = None

    def _run_loop(self, raw_sock):
        """WebSocket read loop — called from the HTTP handler thread.

        Replaces any previous connection, then loops until the socket closes.
        The SDK sends its {type:"ready"} system message first (triggered
        internally on WS open); we must NOT send anything before that.
        """
        with self._lock:
            old = self._sock
            self._sock = raw_sock
        if old and old is not raw_sock:
            try:
                old.sendall(bytes([0x88, 0x00]))
            except Exception:
                pass
        log.info("[IPC] Cast SDK connected — waiting for SDK ready handshake")
        try:
            while True:
                opcode, payload = _ws_read_frame(raw_sock)
                if opcode == 8:   # close
                    break
                if opcode == 9:   # ping → pong
                    try:
                        raw_sock.sendall(bytes([0x8A, 0x00]))
                    except Exception:
                        break
                    continue
                if opcode != 1:   # not text
                    continue
                try:
                    msg = json.loads(payload.decode("utf-8"))
                except Exception:
                    continue
                self._dispatch(msg)
        except Exception as exc:
            log.debug("[IPC] Connection closed: %s", exc)
        finally:
            self._stop_heartbeat()
            with self._lock:
                if self._sock is raw_sock:
                    self._sock = None
            if self.on_sdk_disconnected:
                try:
                    self.on_sdk_disconnected()
                except Exception as exc:
                    log.warning("[IPC] on_sdk_disconnected error: %s", exc)
            log.info("[IPC] Cast SDK disconnected")

    def _dispatch(self, msg: dict):
        """Route an incoming {namespace, senderId, data} IPC message."""
        ns = msg.get("namespace", "")
        sender_id = msg.get("senderId", "")
        raw_data = msg.get("data", "")

        # Validate envelope — all three fields are required
        if not ns or not sender_id or raw_data == "":
            log.debug("[IPC] Dropping malformed message: %s", msg)
            return

        if ns == _IPC_NS_SYSTEM:
            # data is a JSON-encoded string of the system event object
            try:
                data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
            except Exception:
                log.debug("[IPC] Failed to parse system data: %s", raw_data)
                return

            msg_type = data.get("type", "")

            if msg_type == "ready":
                active_ns = data.get("activeNamespaces", [])
                self.active_namespaces = active_ns
                log.info(
                    "[IPC] SDK sent 'ready': ver=%s namespaces=%s",
                    data.get("version"), active_ns,
                )
                # Reply with the platform "ready" (app launch info) so the SDK
                # fires its CastReceiverManager.ready event.
                launch = self.launch_info
                if not launch:
                    log.warning("[IPC] launch_info not set — cannot complete ready handshake")
                else:
                    ready_resp = {
                        "type": "ready",
                        "applicationId": launch.get("applicationId", ""),
                        "applicationName": launch.get("applicationName", ""),
                        "sessionId": launch.get("sessionId", ""),
                        "iconUrl": launch.get("iconUrl", ""),
                        "deviceCapabilities": launch.get("deviceCapabilities", {}),
                        "launchedFrom": launch.get("launchedFrom", "CAST"),
                        "launchingSenderId": launch.get("launchingSenderId", ""),
                    }
                    self._sys_send(ready_resp)
                    log.info("[IPC] Sent platform 'ready' to SDK")

                # Fire the on_sdk_ready callback (flushes pending senders/messages)
                if self.on_sdk_ready:
                    try:
                        self.on_sdk_ready()
                    except Exception as exc:
                        log.warning("[IPC] on_sdk_ready error: %s", exc)

            else:
                if msg_type == "startheartbeat":
                    max_inactivity = data.get("maxInactivity", 600)
                    interval = max(30.0, max_inactivity / 2)
                    log.info("[IPC] Starting IPC heartbeat (maxInactivity=%ds, ping every %.0fs)",
                             max_inactivity, interval)
                    self._start_heartbeat(interval)
                elif msg_type == "pong":
                    log.debug("[IPC] Heartbeat pong received")
                else:
                    log.debug("[IPC] System msg type=%s from %s", msg_type, sender_id)

        else:
            # Non-system namespace (e.g. media): forward payload to callback.
            # raw_data is already the JSON string the SDK sent.
            log.info("[IPC] SDK \u2192 ns=%s  to=%s", ns.split(":")[-1], sender_id)
            if self.on_message:
                try:
                    self.on_message(ns, sender_id, raw_data)
                except Exception as exc:
                    log.warning("[IPC] on_message error: %s", exc)


# Singleton — imported by receiver.py
cast_ipc = CastIpcBridge()


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
                f"<friendlyName>{d.get('name','Hiiragi Cast')}</friendlyName>"
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

        elif path == "/v2/ipc":
            # WebSocket upgrade endpoint for the Cast SDK IPC channel
            upgrade = self.headers.get("Upgrade", "").lower()
            if upgrade == "websocket":
                self._ipc_ws_upgrade()
            else:
                self.send_response(400)
                self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()

    def _ipc_ws_upgrade(self):
        """Perform the WebSocket handshake and hand off to CastIpcBridge."""
        key = self.headers.get("Sec-WebSocket-Key", "")
        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept = base64.b64encode(
            hashlib.sha1((key + magic).encode()).digest()
        ).decode()
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n"
        )
        self.connection.sendall(response.encode())
        log.info("[IPC] WebSocket upgrade complete from %s", self.address_string())
        # Block this thread for the lifetime of the WS connection
        cast_ipc._run_loop(self.connection)


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
        server = ThreadingHTTPServer(("0.0.0.0", self.port), _SetupHandler)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever,
                                        daemon=True, name="SetupServer")
        self._thread.start()
        log.info("Setup HTTP server listening on port %d", self.port)

    def stop(self):
        if self._server:
            self._server.shutdown()
