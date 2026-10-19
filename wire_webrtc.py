"""Cross-platform WebRTC screen-share core.

Windows uses Windows.Graphics.Capture for application windows, prefers DXGI for
monitors, and falls back to MSS. Capture/encode/transport remain isolated so a
future Linux PipeWire backend can replace only LatestFrameCapture.
"""
import asyncio, ctypes, logging, os, queue, threading, time, warnings
from fractions import Fraction
import av
import mss
import numpy as np
from aiortc import AudioStreamTrack, RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription, VideoStreamTrack, MediaStreamError
import aiortc.codecs.h264 as aiortc_h264
from aiortc.rtcrtpsender import RTCRtpSender
from av import VideoFrame
from av import AudioFrame
from av.audio.resampler import AudioResampler
from av.video.reformatter import Interpolation, VideoReformatter

try:
    import dxcam
except ImportError:
    dxcam = None
else:
    # Access-loss warnings are handled by the bounded fallback below. DXcam
    # can otherwise print the same warning hundreds of times into Wire.
    logging.getLogger("dxcam.dxcam").setLevel(logging.ERROR)
    logging.getLogger("dxcam.core.dxgi_duplicator").setLevel(logging.ERROR)

try:
    import soundcard as sc
except ImportError:
    sc = None

try:
    from windows_capture import WindowsCapture
except (ImportError, OSError):
    WindowsCapture = None


_H264_PROBE_LOCK = threading.Lock()
_H264_PROBE_COMPLETE = False
_H264_HARDWARE_ENCODER = None
_PREFER_H264_HARDWARE = True
_DIRECTORY_TURN = None


def configure_turn(value):
    """Accept short-lived TURN credentials only from the authenticated directory."""
    global _DIRECTORY_TURN
    if not isinstance(value, dict):
        _DIRECTORY_TURN = None
        return False
    urls = value.get("urls")
    if isinstance(urls, str):
        urls = [urls]
    username, credential = value.get("username"), value.get("credential")
    if (not isinstance(urls, list) or not urls or len(urls) > 4
            or not all(isinstance(url, str) and url.startswith(("turn:", "turns:")) and len(url) <= 300 for url in urls)
            or not isinstance(username, str) or not 1 <= len(username) <= 200
            or not isinstance(credential, str) or not 1 <= len(credential) <= 300):
        _DIRECTORY_TURN = None
        return False
    _DIRECTORY_TURN = RTCIceServer(urls=urls, username=username, credential=credential)
    return True


def _configure_h264_context(name, width, height, bitrate):
    """Create one low-latency H.264 context without assuming a GPU vendor."""
    codec = av.CodecContext.create(name, "w")
    codec.width, codec.height = width, height
    codec.bit_rate = bitrate
    codec.pix_fmt = "yuv420p"
    codec.framerate = Fraction(aiortc_h264.MAX_FRAME_RATE, 1)
    codec.time_base = Fraction(1, aiortc_h264.MAX_FRAME_RATE)
    if name == "h264_nvenc":
        codec.options = {"preset": "p1", "tune": "ull", "rc": "cbr", "zerolatency": "1"}
    elif name == "h264_amf":
        codec.options = {"usage": "ultralowlatency", "quality": "speed", "rc": "cbr"}
    elif name == "h264_qsv":
        codec.options = {"preset": "veryfast", "look_ahead": "0", "async_depth": "1"}
    else:
        codec.options = {"level": "42", "tune": "zerolatency"}
    codec.profile = "Baseline"
    return codec


def probe_h264_hardware():
    """Return an encoder only after it successfully encodes a real test frame."""
    global _H264_PROBE_COMPLETE, _H264_HARDWARE_ENCODER
    with _H264_PROBE_LOCK:
        if _H264_PROBE_COMPLETE:
            return _H264_HARDWARE_ENCODER
        _H264_PROBE_COMPLETE = True
        for name in ("h264_nvenc", "h264_amf", "h264_qsv"):
            try:
                # Some hardware encoders reject tiny synthetic sizes or delay
                # their first packet, so verify with three real 640x360 frames.
                codec = _configure_h264_context(name, 640, 360, 1_000_000)
                packets = []
                for index in range(3):
                    frame = VideoFrame(640, 360, "yuv420p")
                    frame.pts, frame.time_base = index * 3_000, Fraction(1, 90_000)
                    packets.extend(codec.encode(frame))
                packets.extend(codec.encode(None))
                if packets:
                    _H264_HARDWARE_ENCODER = name
                    break
            except (av.FFmpegError, ValueError):
                continue
        return _H264_HARDWARE_ENCODER


def _wire_h264_encode_frame(self, frame, force_keyframe):
    """Use a verified hardware H.264 encoder, with transparent x264 fallback."""
    if self.codec and (frame.width != self.codec.width or frame.height != self.codec.height
                       or abs(self.target_bitrate - self.codec.bit_rate) / self.codec.bit_rate > 0.1):
        self.buffer_data = b""
        self.buffer_pts = None
        self.codec = None
    frame.pict_type = av.video.frame.PictureType.I if force_keyframe else av.video.frame.PictureType.NONE
    hardware_name = probe_h264_hardware() if _PREFER_H264_HARDWARE else None
    if self.codec is None and hardware_name:
        try:
            self.codec = _configure_h264_context(hardware_name, frame.width, frame.height, self.target_bitrate)
        except (av.FFmpegError, ValueError):
            self.codec = None
    if self.codec is None:
        self.codec = _configure_h264_context("libx264", frame.width, frame.height, self.target_bitrate)
    try:
        data = b"".join(bytes(packet) for packet in self.codec.encode(frame))
    except av.FFmpegError:
        # A driver can disappear or reject a resolution after the initial
        # probe. Keep the share alive by switching to aiortc's x264 path.
        self.codec = _configure_h264_context("libx264", frame.width, frame.height, self.target_bitrate)
        data = b"".join(bytes(packet) for packet in self.codec.encode(frame))
    if data:
        yield from self._split_bitstream(data)


# aiortc does not yet expose a public per-sender hardware encoder selector.
# Patch only its H.264 frame hook, preserving the stock encoder as fallback.
aiortc_h264.H264Encoder._encode_frame = _wire_h264_encode_frame


def ice_configuration():
    """Use STUN for direct internet candidates; TURN is opt-in by environment.

    The directory only signals encrypted SDP. STUN lets endpoints learn their
    public UDP mapping; media remains DTLS-SRTP encrypted peer-to-peer. A host
    can provide its own TURN service without baking credentials into Wire:
    WIRE_TURN_URL, WIRE_TURN_USERNAME, and WIRE_TURN_CREDENTIAL.
    """
    servers = [RTCIceServer(urls=["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"])]
    turn_url = os.environ.get("WIRE_TURN_URL", "").strip()
    if turn_url:
        servers.append(RTCIceServer(urls=[turn_url], username=os.environ.get("WIRE_TURN_USERNAME"), credential=os.environ.get("WIRE_TURN_CREDENTIAL")))
    elif _DIRECTORY_TURN:
        servers.append(_DIRECTORY_TURN)
    return RTCConfiguration(iceServers=servers)


def network_diagnostics(timeout=20):
    """Gather real ICE candidates and prove whether the configured TURN responds."""
    async def probe():
        pc = RTCPeerConnection(ice_configuration())
        try:
            pc.createDataChannel("wire-diagnostic")
            await pc.setLocalDescription(await pc.createOffer())
            gatherer = pc.sctp.transport.transport.iceGatherer
            candidates = gatherer.getLocalCandidates()
            kinds = sorted({candidate.type for candidate in candidates})
            return {"candidate_types": kinds, "turn_configured": bool(_DIRECTORY_TURN or os.environ.get("WIRE_TURN_URL")),
                    "turn_reachable": "relay" in kinds}
        finally:
            await pc.close()
    return asyncio.run(asyncio.wait_for(probe(), timeout=timeout))


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
    def __init__(self, width, height, fps, stats, monitor_index=1, window_name=None, window_hwnd=None):
        self.width, self.height, self.fps = width, height, fps
        self.stats = stats
        self.monitor_index = monitor_index
        self.window_name = window_name
        self.window_hwnd = window_hwnd
        self.frame = None; self.sequence = 0; self.lock = threading.Lock(); self.stop = threading.Event()
        self.paused = threading.Event()
        self.reformatter = VideoReformatter()
        self.backend = "mss"
        self.thread = threading.Thread(target=self._run, daemon=True)
    def start(self): self.thread.start()
    def _publish(self, raw, monitor, capture_cursor=True):
        began = time.monotonic()
        if capture_cursor:
            draw_windows_cursor(raw, monitor)
        with self.lock:
            width, height = self.width, self.height
        # Resize and convert on the capture worker.  Doing this in
        # ScreenTrack.recv serialized CPU preprocessing with WebRTC/NVENC and
        # capped a 1080p60 share well below its requested frame rate.  The
        # converted AV frame owns its buffers, so DXcam's ring-buffer image no
        # longer needs another full-resolution numpy copy either.
        frame = VideoFrame.from_ndarray(raw, format="bgra")
        frame = self.reformatter.reformat(
            frame, width=width, height=height, format="yuv420p",
            interpolation=Interpolation.FAST_BILINEAR,
        )
        with self.lock:
            self.sequence += 1
            self.frame = (frame, self.sequence)
        self.stats.record_capture(time.monotonic() - began)

    def _run_wgc(self):
        """Capture one application through Windows.Graphics.Capture."""
        if WindowsCapture is None or not (self.window_name or self.window_hwnd):
            raise RuntimeError("Windows.Graphics.Capture is unavailable")
        # windows-capture's minimum interval is applied in addition to callback
        # processing.  Reserve a small conversion allowance here and let
        # ScreenTrack perform the exact output pacing / stale-frame dropping.
        # A full 17 ms wait plus a 3-5 ms scale step capped real 60 FPS shares
        # around 45 FPS.
        capture = WindowsCapture(cursor_capture=True, draw_border=False,
                                 minimum_update_interval=max(1, round(1000 / self.fps) - 10),
                                 window_name=None if self.window_hwnd else self.window_name,
                                 window_hwnd=self.window_hwnd)

        @capture.event
        def on_frame_arrived(frame, capture_control):
            if self.stop.is_set():
                capture_control.stop()
                return
            if not self.paused.is_set():
                self._publish(frame.frame_buffer, {"left": 0, "top": 0}, capture_cursor=False)

        @capture.event
        def on_closed():
            self.stop.set()

        self.backend = "windows-graphics-capture"
        control = capture.start_free_threaded()
        self.stop.wait()
        control.stop()
        control.wait()

    def _run_dxcam(self):
        # DXcam uses Windows Desktop Duplication. It is much faster than a GDI
        # screenshot on high-refresh displays, but may be unavailable on older
        # drivers / remote desktop sessions, where MSS remains the fallback.
        with mss.mss() as cap:
            monitors = cap.monitors
            mon = monitors[min(max(1, self.monitor_index), len(monitors) - 1)]
        camera = dxcam.create(output_idx=max(0, self.monitor_index - 1), output_color="BGRA", max_buffer_len=2)
        try:
            camera.start(target_fps=min(self.fps, 120), video_mode=False)
            timestamp = None
            last_frame_available = time.monotonic()
            while not self.stop.is_set():
                if self.paused.is_set():
                    time.sleep(0.02)
                    continue
                # Conversion completes synchronously before DXcam can reuse
                # its ring slot, so a borrowed view avoids a 14 MB copy for a
                # 2560x1440 BGRA desktop on every frame.
                item = camera.get_latest_frame(copy=False, with_timestamp=True)
                if item is None:
                    # DXGI access loss can leave DXcam retrying forever without
                    # raising. Fall back before it floods stderr or hangs /share.
                    if time.monotonic() - last_frame_available > 0.75:
                        raise RuntimeError("DXGI capture stopped producing frames")
                    time.sleep(0.001)
                    continue
                raw, next_timestamp = item
                last_frame_available = time.monotonic()
                if next_timestamp == timestamp:
                    time.sleep(0.001)
                    continue
                timestamp = next_timestamp
                self._publish(raw, mon)
        finally:
            try:
                camera.stop()
                camera.release()
            except Exception:
                pass

    def _run_mss(self):
        interval = 1 / self.fps
        with mss.mss() as cap:
            # mss index 0 is the virtual desktop; real displays start at 1.
            mon = cap.monitors[min(max(1, self.monitor_index), len(cap.monitors) - 1)]
            while not self.stop.is_set():
                if self.paused.is_set():
                    time.sleep(0.02)
                    continue
                began = time.monotonic()
                shot = cap.grab(mon)
                # BGRA buffer is passed straight to PyAV; no Pillow/JPEG/base64 step.
                raw = np.asarray(shot)
                self._publish(raw, mon)
                time.sleep(max(0, interval - (time.monotonic() - began)))

    def _run(self):
        if os.name == "nt" and (self.window_name or self.window_hwnd):
            try:
                self._run_wgc()
                return
            except Exception:
                # If a remembered window was closed, fall back to the selected
                # monitor so /share still works instead of crashing.
                self.backend = "mss"
        if os.name == "nt" and dxcam is not None:
            try:
                self.backend = "dxgi"
                self._run_dxcam()
                return
            except Exception:
                # A capture backend must never prevent sharing on a low-end
                # PC, virtual machine, RDP session, or unsupported adapter.
                self.backend = "mss"
        self._run_mss()
    def latest(self):
        with self.lock: return self.frame
    def set_paused(self, paused):
        self.paused.set() if paused else self.paused.clear()
    def set_quality(self, width, height, fps):
        with self.lock:
            self.width, self.height, self.fps = width, height, fps
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

    def reset(self):
        with self.lock:
            self.started = time.monotonic()
            self.capture_frames = self.sent_frames = self.received_frames = 0
            self.capture_ms = self.encode_ms = 0.0

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
        self.timestamp = 0
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
            if item is None or item[1] == self.last_sequence:
                await asyncio.sleep(min(0.005, interval))
                continue
            frame, sequence = item
            self.last_sequence = sequence
            self.next_frame_at = max(self.next_frame_at + interval, time.monotonic())
            # RTP timestamps must be a small, monotonic media timeline. Using
            # Unix wall-clock values made FFmpeg/WebRTC pace some shares at a
            # few FPS despite capture and encode being fast enough.
            self.timestamp += round(90_000 / self.capture.fps)
            frame.pts = self.timestamp; frame.time_base = Fraction(1, 90_000)
            self.capture.stats.record_sent(time.monotonic() - began)
            return frame


class SystemAudioCapture:
    """Bounded WASAPI loopback capture; a slow sender drops old audio blocks."""
    def __init__(self):
        if os.name != "nt" or sc is None:
            raise RuntimeError("system audio sharing is unavailable on this computer")
        self.error = None
        self.ready = threading.Event()
        self.blocks = queue.Queue(maxsize=3)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, name="wire-system-audio", daemon=True)
        self.thread.start()
        if not self.ready.wait(3) or self.error:
            self.stop.set()
            raise RuntimeError(f"Windows system audio capture failed: {self.error or 'startup timed out'}")

    def _run(self):
        com_initialized = False
        try:
            result = ctypes.windll.ole32.CoInitializeEx(None, 0)
            if result not in (0, 1):
                raise OSError(f"COM initialization failed: 0x{result & 0xffffffff:08x}")
            com_initialized = True
            # Resolve and activate the WASAPI endpoint on its owning thread;
            # COM-backed audio objects must not be created on one thread and
            # then used from another.
            speaker = sc.default_speaker()
            if speaker is None:
                raise RuntimeError("no default Windows speaker is available")
            loopback = sc.get_microphone(speaker.id, include_loopback=True)
            if loopback is None or not loopback.isloopback:
                raise RuntimeError("Windows WASAPI loopback capture is unavailable")
            with warnings.catch_warnings():
                # A bounded queue intentionally drops late loopback blocks.
                # Soundcard reports that recoverable condition per block; do
                # not flood the terminal while WebRTC continues normally.
                warnings.simplefilter("ignore", sc.SoundcardRuntimeWarning)
                with loopback.recorder(samplerate=48_000, channels=2, blocksize=960) as recorder:
                    self.ready.set()
                    while not self.stop.is_set():
                        block = recorder.record(numframes=960)
                        try:
                            while self.blocks.full():
                                self.blocks.get_nowait()
                            self.blocks.put_nowait(block)
                        except queue.Empty:
                            pass
        except Exception as exc:
            self.error = exc
            self.stop.set()
            self.ready.set()
        finally:
            if com_initialized:
                ctypes.windll.ole32.CoUninitialize()

    def get(self):
        while not self.stop.is_set():
            try:
                return self.blocks.get(timeout=0.1)
            except queue.Empty:
                continue
        raise MediaStreamError from self.error

    def close(self):
        self.stop.set()
        if self.thread.is_alive() and threading.current_thread() is not self.thread:
            self.thread.join(timeout=2)


class SystemAudioTrack(AudioStreamTrack):
    def __init__(self, capture):
        super().__init__()
        self.capture = capture
        self.timestamp = 0

    async def recv(self):
        samples = await asyncio.to_thread(self.capture.get)
        pcm = np.clip(samples, -1, 1)
        pcm = (pcm * 32767).astype(np.int16, copy=False)
        frame = AudioFrame.from_ndarray(pcm.reshape(1, -1), format="s16", layout="stereo")
        frame.sample_rate = 48_000
        frame.pts = self.timestamp
        frame.time_base = Fraction(1, 48_000)
        self.timestamp += len(samples)
        return frame


class SystemAudioPlayback:
    """Dedicated COM/WASAPI output worker with a bounded low-latency queue."""
    def __init__(self):
        self.blocks = queue.Queue(maxsize=5)
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._run, name="wire-system-audio-playback", daemon=True)
        self.thread.start()
        if not self.ready.wait(3) or self.error:
            self.stop.set()
            raise RuntimeError(f"Windows system audio playback failed: {self.error or 'startup timed out'}")

    def _run(self):
        com_initialized = False
        try:
            result = ctypes.windll.ole32.CoInitializeEx(None, 0)
            if result not in (0, 1):
                raise OSError(f"COM initialization failed: 0x{result & 0xffffffff:08x}")
            com_initialized = True
            speaker = sc.default_speaker()
            if speaker is None:
                raise RuntimeError("no default Windows speaker is available")
            with speaker.player(samplerate=48_000, channels=2, blocksize=960) as player:
                self.ready.set()
                while not self.stop.is_set():
                    try:
                        player.play(self.blocks.get(timeout=0.1))
                    except queue.Empty:
                        continue
        except Exception as exc:
            self.error = exc
            self.stop.set()
            self.ready.set()
        finally:
            if com_initialized:
                ctypes.windll.ole32.CoUninitialize()

    def put(self, block):
        try:
            while self.blocks.full():
                self.blocks.get_nowait()
            self.blocks.put_nowait(block)
        except queue.Empty:
            pass

    def close(self):
        self.stop.set()
        if self.thread.is_alive() and threading.current_thread() is not self.thread:
            self.thread.join(timeout=2)


class WebRTCShare:
    def __init__(self, signal, on_frame, on_state, width, height, fps, monitor_index=1, codec="auto", bitrate=8_000_000, hardware=True, adaptive=False, system_audio=False, window_name=None, window_hwnd=None):
        self.signal, self.on_frame, self.on_state = signal, on_frame, on_state
        self.width, self.height, self.fps = width, height, fps
        self.monitor_index = monitor_index
        self.window_name = window_name
        self.window_hwnd = window_hwnd
        self.codec_requested = str(codec).upper()
        self.hardware_requested = bool(hardware)
        self.adaptive = bool(adaptive)
        self.system_audio = bool(system_audio)
        self.adaptation = "none"
        self.codec_used = "auto"
        # aiortc's bundled video encoders cap their validated operating range
        # at 0.5-20 Mbps. WebRTC congestion control can lower this as needed.
        self.target_bitrate = max(500_000, min(int(bitrate), 20_000_000))
        self.sender = None
        self.encoder_used = "pending"
        self.loop = asyncio.new_event_loop(); self.pc = None; self.capture = None; self.audio_capture = None
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
        self.pc = RTCPeerConnection(ice_configuration())
        @self.pc.on("connectionstatechange")
        async def state():
            self.stats.state = self.pc.connectionState
            if self.pc.connectionState == "connected":
                # ICE setup can take several seconds; /share stats should
                # describe the active share, not the connection wait.
                self.stats.reset()
            self.on_state(self.pc.connectionState)
        @self.pc.on("track")
        def track(track):
            if track.kind == "video": asyncio.create_task(self._receive(track))
            elif track.kind == "audio": asyncio.create_task(self._receive_audio(track))
        return self.pc
    async def _receive(self, track):
        try:
            while True:
                frame = await track.recv()
                self.stats.record_received()
                self.on_frame(frame.to_ndarray(format="rgb24"))
        except (MediaStreamError, asyncio.CancelledError):
            self.on_state("stream ended")
    async def _receive_audio(self, track):
        if os.name != "nt" or sc is None:
            return
        resampler = AudioResampler(format="flt", layout="stereo", rate=48_000)
        playback = None
        try:
            playback = SystemAudioPlayback()
            while True:
                frame = await track.recv()
                for converted in resampler.resample(frame):
                    playback.put(converted.to_ndarray().reshape(-1, 2))
        except (MediaStreamError, asyncio.CancelledError):
            return
        except Exception:
            self.on_state("system audio unavailable")
        finally:
            if playback:
                playback.close()
    async def offer(self):
        global _PREFER_H264_HARDWARE
        _PREFER_H264_HARDWARE = self.hardware_requested
        pc = await self._pc(); self.capture = LatestFrameCapture(self.width, self.height, self.fps, self.stats, self.monitor_index, self.window_name, self.window_hwnd); self.capture.start()
        transceiver = pc.addTransceiver(ScreenTrack(self.capture), direction="sendonly")
        self.sender = transceiver.sender
        preferences = self.codec_preferences()
        if preferences:
            transceiver.setCodecPreferences(preferences)
        if self.system_audio:
            self.audio_capture = SystemAudioCapture()
            pc.addTransceiver(SystemAudioTrack(self.audio_capture), direction="sendonly")
        offer = await pc.createOffer(); await pc.setLocalDescription(offer)
        return {"sdp": pc.localDescription.sdp, "type": pc.localDescription.type, "resolution": [self.width, self.height], "fps": self.fps, "codec": self.codec_used, "bitrate": self.target_bitrate, "system_audio": self.system_audio, "source": "window" if self.window_name else "monitor"}
    async def answer(self, offer):
        pc = await self._pc(); await pc.setRemoteDescription(RTCSessionDescription(offer["sdp"], offer["type"]))
        answer = await pc.createAnswer(); await pc.setLocalDescription(answer)
        return {"sdp": pc.localDescription.sdp, "type": pc.localDescription.type}
    async def remote(self, answer):
        await self.pc.setRemoteDescription(RTCSessionDescription(answer["sdp"], answer["type"]))
        asyncio.create_task(self._apply_encoder_bitrate())
        if self.adaptive:
            asyncio.create_task(self._adapt_quality())

    async def _adapt_quality(self):
        """Lower an unsustainable automatic profile without reacting to a static desktop."""
        previous_capture = previous_sent = 0
        slow_intervals = 0
        while not self.closed.is_set() and self.capture:
            await asyncio.sleep(5)
            with self.stats.lock:
                captured, sent = self.stats.capture_frames, self.stats.sent_frames
                capture_ms = self.stats.capture_ms / max(1, captured)
            capture_rate = (captured - previous_capture) / 5
            send_rate = (sent - previous_sent) / 5
            previous_capture, previous_sent = captured, sent
            target = self.capture.fps
            # Low frame counts with cheap capture generally mean the desktop
            # is static, not that the machine is overloaded.
            overloaded = capture_ms > (1000 / target) * 0.75
            encoder_slow = capture_rate >= target * 0.75 and send_rate < target * 0.70
            slow_intervals = slow_intervals + 1 if overloaded or encoder_slow else 0
            if slow_intervals < 2:
                continue
            width, height, fps = self.capture.width, self.capture.height, self.capture.fps
            if fps > 30:
                fps = 30
            elif width > 1920:
                width, height = (1920, 1080)
            elif width > 1280:
                width, height = (1280, 720)
            else:
                return
            self.capture.set_quality(width, height, fps)
            self.width, self.height, self.fps = width, height, fps
            self.adaptation = f"{width}x{height}@{fps}"
            self.on_state(f"automatic quality adjusted to {self.adaptation}")
            slow_intervals = 0

    async def _apply_encoder_bitrate(self):
        """Apply the chosen starting rate once aiortc creates its encoder."""
        for _ in range(100):
            if self.closed.is_set():
                return
            encoder = getattr(self.sender, "_RTCRtpSender__encoder", None) if self.sender else None
            if encoder and hasattr(encoder, "target_bitrate"):
                encoder.target_bitrate = self.target_bitrate
                self._update_encoder_name(encoder)
                return
            await asyncio.sleep(0.05)

    def _update_encoder_name(self, encoder=None):
        encoder = encoder or (getattr(self.sender, "_RTCRtpSender__encoder", None) if self.sender else None)
        context = getattr(encoder, "codec", None)
        if context and getattr(context, "name", None):
            self.encoder_used = str(context.name)
    async def _stats(self):
        self._update_encoder_name()
        result = self.stats.snapshot()
        if not self.pc:
            return result
        report = await self.pc.getStats()
        result["adaptation"] = self.adaptation
        for entry in report.values():
            if entry.type in ("inbound-rtp", "outbound-rtp") and getattr(entry, "kind", None) == "video":
                result["bitrate_bytes"] = getattr(entry, "bytesSent", getattr(entry, "bytesReceived", 0))
                result["packets_lost"] = getattr(entry, "packetsLost", 0)
            if entry.type == "remote-inbound-rtp" and getattr(entry, "kind", None) == "video":
                result["rtt_ms"] = round(getattr(entry, "roundTripTime", 0) * 1000)
        try:
            transports = [item.sender.transport.transport for item in self.pc.getTransceivers() if item.sender.transport]
            pairs = [pair for transport in transports for pair in getattr(transport._connection, "_nominated", {}).values()]
            if pairs:
                local_type = pairs[0].local_candidate.type
                remote_type = pairs[0].remote_candidate.type
                result["route"] = "TURN RELAY" if "relay" in (local_type, remote_type) else "DIRECT"
                result["candidate_types"] = f"{local_type}/{remote_type}"
        except (AttributeError, TypeError):
            pass
        return result

    def snapshot(self):
        if self.loop.is_closed():
            return self.stats.snapshot()
        try:
            return self.call(self._stats()).result(timeout=1)
        except Exception:
            return self.stats.snapshot()

    def set_paused(self, paused):
        if not self.capture:
            return False
        self.capture.set_paused(paused)
        return True

    async def _shutdown(self):
        if self.capture:
            self.capture.close()
        if self.audio_capture:
            self.audio_capture.close()
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
