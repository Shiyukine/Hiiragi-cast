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

# ── YouTube URL resolution (requires yt-dlp: pip install yt-dlp) ──────────────
_YT_RE = re.compile(
    r'(?:youtube\.com/(?:watch\?.*?v=|shorts/|embed/)|youtu\.be/)([A-Za-z0-9_-]{11})'
)


def _is_youtube(url: str) -> bool:
    """True for youtube.com/youtu.be URLs or bare 11-char video IDs."""
    if _YT_RE.search(url):
        return True
    # bare 11-char video ID (alphanumeric + - _)
    return bool(re.fullmatch(r'[A-Za-z0-9_-]{11}', url))


def _to_youtube_url(raw: str) -> str:
    """Normalise any YouTube URL or bare video ID to a canonical watch URL."""
    m = _YT_RE.search(raw)
    if m:
        return f'https://www.youtube.com/watch?v={m.group(1)}'
    return f'https://www.youtube.com/watch?v={raw}'  # assume bare ID


def _resolve_youtube(url: str) -> tuple:
    """Use yt-dlp to extract a direct stream URL from a YouTube URL.
    Returns (stream_url, title).  Falls back to (url, '') on failure.
    """
    try:
        import yt_dlp  # soft dependency
        ydl_opts = {
            'format': 'b[ext=mp4]/b/best',  # single-file stream, no merge needed
            'quiet': True,
            'no_warnings': True,
        }
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            direct = info.get('url', '')
            if not direct and 'requested_formats' in info:
                direct = info['requested_formats'][0].get('url', '')
            title = info.get('title', '')
            return (direct or url, title)
    except ImportError:
        log.warning('[Bridge] yt-dlp not installed — YouTube playback unavailable. '
                    'Run: pip install yt-dlp')
    except Exception as exc:
        log.warning('[Bridge] yt-dlp resolution failed: %s', exc)
    return (url, '')


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

        # Resolve YouTube URLs to direct streams via yt-dlp
        if _is_youtube(content_id):
            yt_url = _to_youtube_url(content_id)
            log.info('[Bridge] Resolving YouTube URL: %s', yt_url)
            resolved, yt_title = _resolve_youtube(yt_url)
            content_id = resolved
            content_type = content_type or 'video/mp4'
            if not title and yt_title:
                title = yt_title

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
