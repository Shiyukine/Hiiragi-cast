"""
Cast V2 Test Client
Connects to the receiver and tests authentication + basic commands.

Usage:
    python test_client.py                     # Connect to localhost:8009
    python test_client.py --host 192.168.1.x  # Connect to specific host
"""

import ssl
import socket
import struct
import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cast_channel_pb2

NS_CONNECTION = "urn:x-cast:com.google.cast.tp.connection"
NS_HEARTBEAT = "urn:x-cast:com.google.cast.tp.heartbeat"
NS_RECEIVER = "urn:x-cast:com.google.cast.receiver"
NS_AUTH = "urn:x-cast:com.google.cast.tp.deviceauth"


def send_message(sock, source_id, dest_id, namespace, payload_utf8=None, payload_binary=None):
    """Send a Cast V2 message."""
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

    data = msg.SerializeToString()
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_message(sock, timeout=5.0):
    """Receive a Cast V2 message."""
    sock.settimeout(timeout)
    try:
        header = b""
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return None
            header += chunk

        msg_len = struct.unpack(">I", header)[0]
        data = b""
        while len(data) < msg_len:
            chunk = sock.recv(msg_len - len(data))
            if not chunk:
                return None
            data += chunk

        msg = cast_channel_pb2.CastMessage()
        msg.ParseFromString(data)
        return msg
    except socket.timeout:
        return None


def test_auth(sock):
    """Test device authentication."""
    print("\n[TEST] Sending AuthChallenge...")
    auth_msg = cast_channel_pb2.DeviceAuthMessage()
    auth_msg.challenge.signature_algorithm = cast_channel_pb2.RSASSA_PKCS1v15
    auth_msg.challenge.sender_nonce = os.urandom(32)
    auth_msg.challenge.hash_algorithm = cast_channel_pb2.SHA256

    send_message(sock, "sender-0", "receiver-0", NS_AUTH,
                 payload_binary=auth_msg.SerializeToString())

    response = recv_message(sock)
    if not response:
        print("[FAIL] No auth response received!")
        return False

    if response.namespace != NS_AUTH:
        print(f"[FAIL] Unexpected namespace: {response.namespace}")
        return False

    auth_resp = cast_channel_pb2.DeviceAuthMessage()
    auth_resp.ParseFromString(response.payload_binary)

    if auth_resp.HasField("error"):
        print(f"[FAIL] Auth error: {auth_resp.error.error_type}")
        return False

    if auth_resp.HasField("response"):
        resp = auth_resp.response
        print(f"[PASS] Auth response received!")
        print(f"       Signature: {len(resp.signature)} bytes")
        print(f"       Certificate: {len(resp.client_auth_certificate)} bytes")
        print(f"       Intermediates: {len(resp.intermediate_certificate)}")
        print(f"       Sig algorithm: {resp.signature_algorithm}")
        print(f"       Hash algorithm: {resp.hash_algorithm}")
        return True

    print("[FAIL] No response or error in auth message")
    return False


def test_connect(sock):
    """Test connection establishment."""
    print("\n[TEST] Sending CONNECT...")
    send_message(sock, "sender-0", "receiver-0", NS_CONNECTION,
                 payload_utf8=json.dumps({
                     "type": "CONNECT",
                     "origin": {},
                     "userAgent": "CastTestClient/1.0",
                     "senderInfo": {
                         "sdkType": 2,
                         "version": "15.204.0.5",
                         "browserVersion": "44.0.2403.30",
                         "platform": 4,
                         "connectionType": 1,
                     },
                 }))
    # CONNECT doesn't get a response
    print("[PASS] CONNECT sent (no response expected)")
    return True


def test_heartbeat(sock):
    """Test PING/PONG heartbeat."""
    print("\n[TEST] Sending PING...")
    send_message(sock, "sender-0", "receiver-0", NS_HEARTBEAT,
                 payload_utf8=json.dumps({"type": "PING"}))

    response = recv_message(sock)
    if not response:
        print("[FAIL] No PONG received!")
        return False

    payload = json.loads(response.payload_utf8)
    if payload.get("type") == "PONG":
        print("[PASS] PONG received!")
        return True
    else:
        print(f"[FAIL] Unexpected response: {payload}")
        return False


def test_receiver_status(sock):
    """Test GET_STATUS on receiver namespace."""
    print("\n[TEST] Sending GET_STATUS...")
    send_message(sock, "sender-0", "receiver-0", NS_RECEIVER,
                 payload_utf8=json.dumps({
                     "type": "GET_STATUS",
                     "requestId": 1,
                 }))

    response = recv_message(sock)
    if not response:
        print("[FAIL] No status response!")
        return False

    payload = json.loads(response.payload_utf8)
    if payload.get("type") == "RECEIVER_STATUS":
        status = payload.get("status", {})
        volume = status.get("volume", {})
        apps = status.get("applications", [])
        print("[PASS] RECEIVER_STATUS received!")
        print(f"       Volume: {volume.get('level', '?')}, Muted: {volume.get('muted', '?')}")
        print(f"       Active apps: {len(apps)}")
        return True
    else:
        print(f"[FAIL] Unexpected: {payload.get('type')}")
        return False


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Cast V2 Test Client")
    parser.add_argument("--host", default="127.0.0.1", help="Receiver host")
    parser.add_argument("--port", type=int, default=8009, help="Receiver port")
    args = parser.parse_args()

    print("=" * 60)
    print("  CAST V2 AUTHENTICATION TEST CLIENT")
    print("=" * 60)
    print(f"  Target: {args.host}:{args.port}")
    print("=" * 60)

    # Create TLS connection (don't verify server cert)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print("\n[TEST] Connecting via TLS...")
    try:
        raw_sock = socket.create_connection((args.host, args.port), timeout=10)
        sock = ctx.wrap_socket(raw_sock)
        print(f"[PASS] TLS connected! Version: {sock.version()}, Cipher: {sock.cipher()[0]}")
    except Exception as e:
        print(f"[FAIL] Connection failed: {e}")
        sys.exit(1)

    # Run tests
    results = {}
    tests = [
        ("Authentication", test_auth),
        ("Connection", test_connect),
        ("Heartbeat", test_heartbeat),
        ("Receiver Status", test_receiver_status),
    ]

    for name, test_fn in tests:
        try:
            results[name] = test_fn(sock)
        except Exception as e:
            print(f"[FAIL] {name} error: {e}")
            results[name] = False

    # Summary
    print("\n" + "=" * 60)
    print("  TEST RESULTS")
    print("=" * 60)
    for name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}")
    print("=" * 60)

    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n  {passed}/{total} tests passed")

    if all(results.values()):
        print("\n  ** ALL TESTS PASSED - Authentication is working! **")
    print()

    sock.close()


if __name__ == "__main__":
    main()
