"""
Media Bridge - WebSocket server that forwards Cast media events to the Electron player.

The Python receiver calls bridge.send(event) whenever media state changes.
The Electron app connects to ws://localhost:9000 and receives JSON events:

  { "event": "load",  "contentId": "https://...", "contentType": "video/mp4",
    "title": "...", "currentTime": 0 }
  { "event": "play" }
  { "event": "pause" }
  { "event": "seek",  "currentTime": 12.5 }
  { "event": "stop" }
  { "event": "volume", "level": 0.8, "muted": false }
  { "event": "status", ...full media status... }
"""

import asyncio
import json
import logging
import re
import threading

log = logging.getLogger("MediaBridge")

try:
    import websockets
    _HAS_WEBSOCKETS = True
except ImportError:
    _HAS_WEBSOCKETS = False
    log.warning("websockets not installed — Electron bridge disabled. "
                "Run: pip install websockets")


class MediaBridge:
    """Thread-safe WebSocket broadcaster for media events."""

    def __init__(self, host="localhost", port=9000):
        self.host = host
        self.port = port
        self._clients: set = set()
        self._loop: asyncio.AbstractEventLoop = None
        self._thread: threading.Thread = None
        self._ready = threading.Event()

    # ------------------------------------------------------------------ #
    #  Public API (called from receiver thread)                            #
    # ------------------------------------------------------------------ #

    def start(self):
        """Start the WebSocket server in a background thread."""
        if not _HAS_WEBSOCKETS:
            return
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="MediaBridge")
        self._thread.start()
        self._ready.wait(timeout=5)
        log.info("Media bridge listening on ws://%s:%d", self.host, self.port)

    def send(self, event: dict):
        """Broadcast an event dict to all connected Electron clients."""
        if not _HAS_WEBSOCKETS or not self._loop:
            return
        asyncio.run_coroutine_threadsafe(self._broadcast(json.dumps(event)),
                                         self._loop)

    # Convenience helpers

    def on_load(self, media: dict, current_time: float = 0):
        content_id   = media.get("contentId", "")
        content_type = media.get("contentType", "")
        metadata     = media.get("metadata", {})
        title        = metadata.get("title", "") or metadata.get("metadataType", "")
        subtitle     = metadata.get("subtitle", "")
        duration     = media.get("duration")
        images       = metadata.get("images", [])
        poster       = images[0].get("url", "") if images else ""

        self.send({
            "event": "load",
            "contentId": content_id,
            "contentType": content_type,
            "title": title,
            "subtitle": subtitle,
            "poster": poster,
            "duration": duration,
            "currentTime": current_time,
        })

    def on_play(self):
        self.send({"event": "play"})

    def on_pause(self):
        self.send({"event": "pause"})

    def on_seek(self, current_time: float):
        self.send({"event": "seek", "currentTime": current_time})

    def on_stop(self):
        self.send({"event": "stop"})

    def on_volume(self, level: float, muted: bool):
        self.send({"event": "volume", "level": level, "muted": muted})

    # ------------------------------------------------------------------ #
    #  Internal asyncio loop (runs in background thread)                  #
    # ------------------------------------------------------------------ #

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    async def _serve(self):
        async with websockets.serve(self._handler, self.host, self.port):
            self._ready.set()
            await asyncio.Future()  # run forever

    async def _handler(self, ws):
        addr = ws.remote_address
        log.info("Electron player connected from %s:%d", addr[0], addr[1])
        self._clients.add(ws)
        try:
            async for _ in ws:
                pass   # ignore messages from the player side
        except websockets.ConnectionClosed:
            pass
        finally:
            self._clients.discard(ws)
            log.info("Electron player disconnected (%s:%d)", addr[0], addr[1])

    async def _broadcast(self, message: str):
        dead = set()
        for ws in list(self._clients):
            try:
                await ws.send(message)
            except websockets.ConnectionClosed:
                dead.add(ws)
        self._clients -= dead
