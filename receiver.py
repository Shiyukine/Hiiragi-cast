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

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Add parent path for protobuf import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cast_channel_pb2

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("CastReceiver")

# Cast V2 Namespaces
NS_CONNECTION = "urn:x-cast:com.google.cast.tp.connection"
NS_HEARTBEAT = "urn:x-cast:com.google.cast.tp.heartbeat"
NS_RECEIVER = "urn:x-cast:com.google.cast.receiver"
NS_AUTH = "urn:x-cast:com.google.cast.tp.deviceauth"
NS_MEDIA = "urn:x-cast:com.google.cast.media"
NS_YOUTUBE = "urn:x-cast:com.google.youtube.mdx"
NS_SETUP = "urn:x-cast:com.google.cast.setup"
NS_DISCOVERY = "urn:x-cast:com.google.cast.receiver.discovery"


class CastReceiver:
    """Minimal Cast V2 receiver with TLS authentication."""

    def __init__(self, cert_file, key_file, peer_cert_file=None, port=8009,
                 auth_crt_file=None, signatures_file=None, media_bridge=None,
                 friendly_name="Hiiragi Cast", device_id=None):
        self.cert_file = cert_file
        self.key_file = key_file
        self.peer_cert_file = peer_cert_file
        self.auth_crt_file = auth_crt_file
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
        except (BrokenPipeError, OSError) as e:
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
            log.info("[%s] << HEARTBEAT: %s", client_id, payload.get("type"))
            self._handle_heartbeat(sock, msg, payload)
        elif ns == NS_RECEIVER:
            payload = json.loads(msg.payload_utf8)
            log.info("[%s] << RECEIVER: %s", client_id, payload.get("type"))
            self._handle_receiver(sock, msg, payload)
        elif ns == NS_MEDIA:
            payload = json.loads(msg.payload_utf8)
            log.info("[%s] << MEDIA: %s", client_id, payload.get("type"))
            self._handle_media(sock, msg, payload)
        elif ns == NS_YOUTUBE:
            payload = json.loads(msg.payload_utf8)
            log.info("[%s] << YOUTUBE: %s", client_id, payload.get("type"))
            self._handle_youtube(sock, msg, payload)
        elif ns == NS_SETUP:
            payload = json.loads(msg.payload_utf8)
            log.info("[%s] << SETUP: %s", client_id, payload.get("type"))
            self._handle_setup(sock, msg, payload)
        elif ns == NS_DISCOVERY:
            payload = json.loads(msg.payload_utf8)
            log.info("[%s] << DISCOVERY: %s", client_id, payload.get("type"))
            self._handle_discovery(sock, msg, payload)
        else:
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
            # No response needed for CONNECT
        elif msg_type == "CLOSE":
            log.info("  Client requested close: dest=%s", msg.destination_id)
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
            log.info("  >> PONG")

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
            transport_id = "web-" + hashlib.md5(os.urandom(8)).hexdigest()[:6]
            self.media_transport_id = transport_id
            self.media_status = None  # reset media on new launch
            self.applications = [{
                "appId": app_id,
                "displayName": self._app_display_name(app_id),
                "isIdleScreen": False,
                "launchedFromCloud": False,
                "namespaces": [
                    {"name": NS_MEDIA},
                    {"name": NS_YOUTUBE},
                    {"name": "urn:x-cast:com.google.cast.cac"},
                ] if app_id == "233637DE" else [
                    {"name": NS_MEDIA},
                    {"name": "urn:x-cast:com.google.cast.cac"},
                ],
                "sessionId": hashlib.md5(os.urandom(16)).hexdigest(),
                "statusText": "Ready To Cast",
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

        elif msg_type == "STOP":
            app_session_id = payload.get("sessionId")
            # Only stop if it matches the active session
            if app_session_id and self.applications and \
               self.applications[0].get("sessionId") == app_session_id:
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

        else:
            log.info("  Unhandled receiver message type: %s", msg_type)

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

    def _app_display_name(self, app_id):
        """Return a friendly display name for known app IDs."""
        _known = {
            "CC1AD845": "Default Media Receiver",
            "E8C28D3C": "Backdrop",
            "YouTube":  "YouTube",
            "233637DE": "YouTube",
            "2DB7CC49": "Google Play Music",
            "4AADC7B0": "YouTube Music",
            "B3DCF968": "Spotify",
            "A9BCCB7C": "VLC",
        }
        return _known.get(app_id, app_id)

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
