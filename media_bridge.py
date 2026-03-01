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
        # Video frame slot: only the latest frame is kept; sending is
        # serialised so at most one ws.send() is in flight at any time.
        # This prevents the asyncio event loop from accumulating a backlog
        # of large binary sends (memory leak + latency).
        self._video_latest: object = None   # bytes or None
        self._video_lock   = threading.Lock()
        self._video_sending: bool = False   # accessed only from asyncio thread
        self._ws_server    = None           # websockets.Server instance

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

    def start_mirror(self):
        """Tell Electron to show the mirror canvas."""
        self.send({"event": "start-mirror"})

    def stop_mirror(self):
        """Tell Electron to hide the mirror canvas."""
        self.send({"event": "stop-mirror"})

    def send_mirror_frame(self, frame_data: bytes):
        """Push a raw video frame to the Electron mirror canvas.

        frame_data: binary-framed RGBA buffer (uint32be width, uint32be height,
        then tight-packed RGBA pixels) produced by webrtc_handler._decode_video.

        Only one ws.send() is ever in flight at a time.  If a new frame arrives
        while the previous send is still running, the previous pending frame is
        discarded (latest-wins), preventing queue growth and memory leaks.
        """
        if not _HAS_WEBSOCKETS or not self._loop:
            return
        with self._video_lock:
            self._video_latest = frame_data          # overwrite any waiting frame
        self._loop.call_soon_threadsafe(self._drain_video)

    def _drain_video(self):
        """Called from asyncio thread via call_soon_threadsafe.
        Starts a send if none is in flight; otherwise the in-flight send
        will pick up the latest frame itself when it completes.
        """
        if self._video_sending:
            return  # _do_send_video will re-drain on completion
        with self._video_lock:
            data = self._video_latest
            self._video_latest = None
        if data:
            self._video_sending = True
            self._loop.create_task(self._do_send_video(data))

    async def _do_send_video(self, data: bytes):
        """Send one frame then immediately drain any frame that arrived
        while the send was in progress — ensuring zero backlog."""
        try:
            await self._broadcast_binary(data)
        finally:
            # Check for a frame that arrived while we were sending
            with self._video_lock:
                next_data = self._video_latest
                self._video_latest = None
            if next_data:
                # Keep _video_sending=True and send the next frame
                self._loop.create_task(self._do_send_video(next_data))
            else:
                self._video_sending = False

    def load_url(self, url: str):
        """Tell Electron to open the Cast receiver app in a new window."""
        self.send({"event": "load-url", "url": url})

    def stop_webview(self):
        """Tell Electron to close the Cast receiver window."""
        self.send({"event": "stop-url"})

    # ------------------------------------------------------------------ #
    #  Internal asyncio loop (runs in background thread)                  #
    # ------------------------------------------------------------------ #

    def stop(self):
        """Cleanly stop the WebSocket server and its event loop."""
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self):
        # Use SelectorEventLoop on Windows — ProactorEventLoop (the default)
        # modifies the Windows console mode for async I/O and does not restore
        # it if the loop is abandoned, leaving PowerShell non-interactive after
        # process exit.
        import sys as _sys
        if _sys.platform == "win32":
            self._loop = asyncio.SelectorEventLoop()
        else:
            self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        # Start the WebSocket server, then run_forever().
        # run_forever() returns cleanly when loop.stop() is called (from stop()),
        # unlike run_until_complete(Future()) which raises RuntimeError on stop().
        self._loop.run_until_complete(self._start_server())
        self._loop.run_forever()
        # Cleanup after loop.stop()
        try:
            if self._ws_server:
                self._ws_server.close()
                self._loop.run_until_complete(self._ws_server.wait_closed())
        except Exception:
            pass
        self._loop.close()

    async def _start_server(self):
        self._ws_server = await websockets.serve(self._handler, self.host, self.port)
        self._ready.set()

    async def _serve(self):
        # Kept for compatibility; not used in normal operation.
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

    async def _broadcast_binary(self, data: bytes):
        """Broadcast a binary WebSocket frame (raw bytes, no JSON wrapping)."""
        dead = set()
        for ws in list(self._clients):
            try:
                await ws.send(data)
            except websockets.ConnectionClosed:
                dead.add(ws)
        self._clients -= dead
