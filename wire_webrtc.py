"""Cross-platform WebRTC screen-share core.

Windows currently uses MSS capture.  Capture/encode/transport are isolated here so a
Windows.Graphics.Capture/D3D11 backend or Linux PipeWire backend can replace only
LatestFrameCapture later; the signaling/UI layers do not depend on Windows APIs.
"""
import asyncio, ctypes, os, threading, time
from fractions import Fraction
import mss
import numpy as np
from aiortc import RTCPeerConnection, RTCSessionDescription, VideoStreamTrack, MediaStreamError
from aiortc.rtcrtpsender import RTCRtpSender
from aiortc.contrib.media import MediaRelay
from av import VideoFrame


def draw_windows_cursor(frame: np.ndarray, monitor: dict) -> None:
    """Paint a small high-contrast arrow into the BGRA frame without image conversion."""
    if os.name != "nt": return
    class Point(ctypes.Structure): _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
    point = Point()
    if not ctypes.windll.user32.GetCursorPos(ctypes.byref(point)): return
    x, y = point.x - monitor["left"], point.y - monitor["top"]
    if not (0 <= x < frame.shape[1] and 0 <= y < frame.shape[0]): return
    # Coordinates of a standard arrow; first draw a black edge then a white fill.
    for offset, color in ((0, (0, 0, 0, 255)), (1, (255, 255, 255, 255))):
        for row in range(18):
            width = min(row // 2 + 1, 7)
            left, right = x + offset, x + width + offset
            yy = y + row + offset
            if 0 <= yy < frame.shape[0]: frame[yy, max(0, left):min(frame.shape[1], right)] = color


class LatestFrameCapture:
    """One-slot capture queue: slow encoders always receive the newest frame."""
    def __init__(self, width, height, fps, stats, monitor_index=1):
        self.width, self.height, self.fps = width, height, fps
        self.stats = stats
        self.monitor_index = monitor_index
        self.frame = None; self.sequence = 0; self.lock = threading.Lock(); self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
    def start(self): self.thread.start()
    def _run(self):
        interval = 1 / self.fps
        with mss.mss() as cap:
            # mss index 0 is the virtual desktop; real displays start at 1.
            mon = cap.monitors[min(max(1, self.monitor_index), len(cap.monitors) - 1)]
            while not self.stop.is_set():
                began = time.monotonic()
                shot = cap.grab(mon)
                # BGRA buffer is passed straight to PyAV; no Pillow/JPEG/base64 step.
                raw = np.asarray(shot).copy()
                draw_windows_cursor(raw, mon)
                with self.lock:
                    self.sequence += 1
                    self.frame = (raw, shot.size, self.sequence)
                self.stats.record_capture(time.monotonic() - began)
                time.sleep(max(0, interval - (time.monotonic() - began)))
    def latest(self):
        with self.lock: return self.frame
    def close(self):
        self.stop.set()
        if self.thread.is_alive() and threading.current_thread() is not self.thread:
            self.thread.join(timeout=2)


class ShareStats:
    """Thread-safe, low-overhead measurements for /share stats."""
    def __init__(self):
        self.started = time.monotonic(); self.lock = threading.Lock()
        self.capture_frames = self.sent_frames = self.received_frames = 0
        self.capture_ms = self.encode_ms = 0.0
        self.state = "new"

    def record_capture(self, elapsed):
        with self.lock:
            self.capture_frames += 1; self.capture_ms += elapsed * 1000

    def record_sent(self, elapsed):
        with self.lock:
            self.sent_frames += 1; self.encode_ms += elapsed * 1000

    def record_received(self):
        with self.lock: self.received_frames += 1

    def snapshot(self):
        with self.lock:
            seconds = max(0.001, time.monotonic() - self.started)
            return {
                "seconds": seconds, "state": self.state,
                "capture_fps": self.capture_frames / seconds,
                "send_fps": self.sent_frames / seconds,
                "receive_fps": self.received_frames / seconds,
                "capture_ms": self.capture_ms / max(1, self.capture_frames),
                "encode_ms": self.encode_ms / max(1, self.sent_frames),
            }


class ScreenTrack(VideoStreamTrack):
    kind = "video"
    def __init__(self, capture):
        super().__init__()
        self.capture = capture
        self.last_sequence = -1
        self.next_frame_at = time.monotonic()
    async def recv(self):
        # Do not encode the same desktop frame repeatedly when capture is the
        # bottleneck. Repeated frames consumed CPU/GPU without making motion
        # smoother and made weak PCs fall further behind.
        interval = 1 / self.capture.fps
        while True:
            now = time.monotonic()
            if now < self.next_frame_at:
                await asyncio.sleep(self.next_frame_at - now)
            began = time.monotonic()
            item = self.capture.latest()
            if item is None or item[2] == self.last_sequence:
                await asyncio.sleep(min(0.005, interval))
                continue
            raw, _size, sequence = item
            self.last_sequence = sequence
            self.next_frame_at = max(self.next_frame_at + interval, time.monotonic())
            frame = VideoFrame.from_ndarray(raw, format="bgra")
            frame = frame.reformat(width=self.capture.width, height=self.capture.height, format="yuv420p")
            frame.pts = int(time.time() * 90000); frame.time_base = Fraction(1, 90000)
            self.capture.stats.record_sent(time.monotonic() - began)
            return frame


class WebRTCShare:
    def __init__(self, signal, on_frame, on_state, width, height, fps, monitor_index=1, codec="auto", bitrate=8_000_000):
        self.signal, self.on_frame, self.on_state = signal, on_frame, on_state
        self.width, self.height, self.fps = width, height, fps
        self.monitor_index = monitor_index
        self.codec_requested = str(codec).upper()
        self.codec_used = "auto"
        # aiortc's bundled video encoders cap their validated operating range
        # at 0.5-20 Mbps. WebRTC congestion control can lower this as needed.
        self.target_bitrate = max(500_000, min(int(bitrate), 20_000_000))
        self.sender = None
        self.encoder_used = "pending"
        self.loop = asyncio.new_event_loop(); self.pc = None; self.capture = None
        self.stats = ShareStats()
        self.closed = threading.Event(); self.close_lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, daemon=True); self.thread.start()
    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()
        self.loop.run_until_complete(self.loop.shutdown_asyncgens())
        self.loop.close()
    def call(self, coro): return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def codec_preferences(self):
        """Return only codecs the local aiortc/PyAV stack can actually use."""
        try:
            codecs = [item for item in RTCRtpSender.getCapabilities("video").codecs
                      if item.mimeType.lower() not in ("video/rtx", "video/red", "video/ulpfec")]
        except Exception:
            return []
        requested = self.codec_requested
        available = {item.mimeType.rsplit("/", 1)[-1].upper() for item in codecs}
        # H.264 is broadly interoperable and, in this packaged stack, probes
        # NVENC then falls back to x264. Never require a GPU to share.
        preferred = "H264" if requested == "AUTO" and "H264" in available else requested
        selected = [item for item in codecs if item.mimeType.rsplit("/", 1)[-1].upper() == preferred]
        if not selected:
            selected = codecs
            preferred = selected[0].mimeType.rsplit("/", 1)[-1].upper() if selected else "auto"
        self.codec_used = preferred
        return selected
    async def _pc(self):
        if self.pc: return self.pc
        self.pc = RTCPeerConnection()
        @self.pc.on("connectionstatechange")
        async def state():
            self.stats.state = self.pc.connectionState
            self.on_state(self.pc.connectionState)
        @self.pc.on("track")
        def track(track):
            if track.kind == "video": asyncio.create_task(self._receive(track))
        return self.pc
    async def _receive(self, track):
        try:
            while True:
                frame = await track.recv()
                self.stats.record_received()
                self.on_frame(frame.to_ndarray(format="rgb24"))
        except (MediaStreamError, asyncio.CancelledError):
            self.on_state("stream ended")
    async def offer(self):
        pc = await self._pc(); self.capture = LatestFrameCapture(self.width, self.height, self.fps, self.stats, self.monitor_index); self.capture.start()
        transceiver = pc.addTransceiver(ScreenTrack(self.capture), direction="sendonly")
        self.sender = transceiver.sender
        preferences = self.codec_preferences()
        if preferences:
            transceiver.setCodecPreferences(preferences)
        offer = await pc.createOffer(); await pc.setLocalDescription(offer)
        return {"sdp": pc.localDescription.sdp, "type": pc.localDescription.type, "resolution": [self.width, self.height], "fps": self.fps, "codec": self.codec_used, "bitrate": self.target_bitrate}
    async def answer(self, offer):
        pc = await self._pc(); await pc.setRemoteDescription(RTCSessionDescription(offer["sdp"], offer["type"]))
        answer = await pc.createAnswer(); await pc.setLocalDescription(answer)
        return {"sdp": pc.localDescription.sdp, "type": pc.localDescription.type}
    async def remote(self, answer):
        await self.pc.setRemoteDescription(RTCSessionDescription(answer["sdp"], answer["type"]))
        asyncio.create_task(self._apply_encoder_bitrate())

    async def _apply_encoder_bitrate(self):
        """Apply the chosen starting rate once aiortc creates its encoder."""
        for _ in range(100):
            if self.closed.is_set():
                return
            encoder = getattr(self.sender, "_RTCRtpSender__encoder", None) if self.sender else None
            if encoder and hasattr(encoder, "target_bitrate"):
                encoder.target_bitrate = self.target_bitrate
                context = getattr(encoder, "codec", None)
                self.encoder_used = str(getattr(context, "name", "software"))
                return
            await asyncio.sleep(0.05)
    async def _stats(self):
        result = self.stats.snapshot()
        if not self.pc:
            return result
        report = await self.pc.getStats()
        for entry in report.values():
            if entry.type in ("inbound-rtp", "outbound-rtp") and getattr(entry, "kind", None) == "video":
                result["bitrate_bytes"] = getattr(entry, "bytesSent", getattr(entry, "bytesReceived", 0))
                result["packets_lost"] = getattr(entry, "packetsLost", 0)
            if entry.type == "remote-inbound-rtp" and getattr(entry, "kind", None) == "video":
                result["rtt_ms"] = round(getattr(entry, "roundTripTime", 0) * 1000)
        return result

    def snapshot(self):
        if self.loop.is_closed():
            return self.stats.snapshot()
        try:
            return self.call(self._stats()).result(timeout=1)
        except Exception:
            return self.stats.snapshot()

    async def _shutdown(self):
        if self.capture:
            self.capture.close()
        if self.pc:
            await self.pc.close()

    def close(self):
        """Drain aiortc transports before closing the owning asyncio loop."""
        with self.close_lock:
            if self.closed.is_set(): return
            self.closed.set()
            completed = True
            if self.pc and not self.loop.is_closed():
                try: self.call(self._shutdown()).result(timeout=8)
                except Exception: completed = False
            if self.capture: self.capture.close()
            # Do not tear down an event loop while aiortc is still draining its
            # ICE/DTLS tasks. That was the source of the pending-task warnings.
            if completed and not self.loop.is_closed(): self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread.is_alive() and threading.current_thread() is not self.thread:
            self.thread.join(timeout=9)
