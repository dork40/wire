import asyncio
import queue
import threading
import unittest
from unittest import mock

from av import VideoFrame

import numpy as np

from wire_webrtc import LatestFrameCapture, ScreenTrack, ShareStats, SystemAudioTrack, _wgc_capture_process, configure_turn, ice_configuration


class _Capture:
    width = 640
    height = 360
    fps = 30

    def __init__(self):
        self.stats = ShareStats()
        self.frame = (VideoFrame(self.width, self.height, "yuv420p"), 1)

    def latest(self):
        return self.frame


class ScreenTrackTests(unittest.TestCase):
    def test_ready_frame_tuple_is_emitted_with_rtp_timestamp(self):
        track = ScreenTrack(_Capture())
        frame = asyncio.run(track.recv())
        self.assertEqual((frame.width, frame.height), (640, 360))
        self.assertEqual(frame.pts, 3000)
        self.assertEqual(track.capture.stats.snapshot()["send_fps"] > 0, True)

    def test_capture_pause_can_be_resumed_without_restarting_backend(self):
        capture = LatestFrameCapture(640, 360, 30, ShareStats())
        capture.set_paused(True)
        self.assertTrue(capture.paused.is_set())
        capture.set_paused(False)
        self.assertFalse(capture.paused.is_set())
        capture.set_quality(1280, 720, 60)
        self.assertEqual((capture.width, capture.height, capture.fps), (1280, 720, 60))

    def test_authenticated_directory_turn_configuration_is_validated(self):
        self.assertFalse(configure_turn({"urls": ["https://evil.invalid"], "username": "u", "credential": "p"}))
        self.assertTrue(configure_turn({"urls": ["turn:relay.example:3478?transport=udp"], "username": "123:user", "credential": "token"}))
        servers = ice_configuration().iceServers
        self.assertTrue(any(server.username == "123:user" for server in servers))
        configure_turn(None)

    def test_system_audio_track_emits_stereo_48khz_frames(self):
        class Capture:
            def get(self):
                return np.zeros((960, 2), dtype=np.float32)
        frame = asyncio.run(SystemAudioTrack(Capture()).recv())
        self.assertEqual(frame.sample_rate, 48_000)
        self.assertEqual(frame.layout.name, "stereo")
        self.assertEqual(frame.samples, 960)
        self.assertEqual(frame.time_base.numerator, 1)
        self.assertEqual(frame.time_base.denominator, 48_000)

    def test_application_window_uses_windows_graphics_capture_backend(self):
        class NativeFrame:
            frame_buffer = np.full((16, 16, 4), 127, dtype=np.uint8)
        class FakeCapture:
            last_kwargs = None
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                FakeCapture.last_kwargs = kwargs
                self.handlers = {}
            def event(self, callback):
                self.handlers[callback.__name__] = callback
                return callback
            def start(self):
                class Control:
                    def stop(self): pass
                self.handlers["on_frame_arrived"](NativeFrame(), Control())
        class Value:
            def __init__(self, value=0): self.value, self.lock = value, threading.Lock()
            def get_lock(self): return self.lock
        class Memory:
            def __init__(self): self.buf = bytearray(16 * 16 * 4)
            def close(self): pass
        memory, sequence, status, stop, errors = Memory(), Value(), Value(), threading.Event(), queue.Queue()
        with mock.patch("wire_webrtc.WindowsCapture", FakeCapture), \
             mock.patch("wire_webrtc.shared_memory.SharedMemory", return_value=memory), \
             mock.patch("wire_webrtc.ctypes.windll", create=True) as windll:
            windll.ole32.CoInitializeEx.return_value = 0
            windll.combase.RoInitialize.return_value = 0
            _wgc_capture_process(16, 16, 60, "Calculator", None, "test", sequence, status, stop, errors)
        self.assertEqual(status.value, 1)
        self.assertEqual(sequence.value, 1)
        self.assertTrue(any(memory.buf))
        # Reserve time for scale/format conversion instead of adding a full
        # 17 ms WGC wait on top and unintentionally capping 60 FPS near 45.
        self.assertEqual(FakeCapture.last_kwargs["minimum_update_interval"], 7)

    def test_window_capture_never_falls_back_to_full_monitor(self):
        capture = LatestFrameCapture(640, 360, 60, ShareStats(), window_name="Calculator", window_hwnd=123)
        with mock.patch.object(capture, "_run_wgc", side_effect=RuntimeError("WGC unavailable")), \
             mock.patch.object(capture, "_run_dxcam", side_effect=lambda: capture.stop.set()) as dxgi, \
             mock.patch("wire_webrtc.dxcam", object()), mock.patch("wire_webrtc.os.name", "nt"):
            capture._run()
        dxgi.assert_called_once_with()
        self.assertEqual(capture.backend, "dxgi-window")
        self.assertIn("WGC unavailable", capture.backend_error)

        no_handle = LatestFrameCapture(640, 360, 60, ShareStats(), window_name="Missing")
        with mock.patch.object(no_handle, "_run_wgc", side_effect=RuntimeError("WGC unavailable")), \
             mock.patch.object(no_handle, "_run_dxcam") as dxgi, \
             mock.patch.object(no_handle, "_run_mss") as mss, \
             mock.patch("wire_webrtc.dxcam", object()), mock.patch("wire_webrtc.os.name", "nt"):
            no_handle._run()
        dxgi.assert_not_called(); mss.assert_not_called()
        self.assertTrue(no_handle.stop.is_set())

    def test_dxgi_window_capture_produces_a_first_frame_when_static(self):
        class Desktop:
            monitors = [{}, {"left": 0, "top": 0, "width": 1920, "height": 1080}]
            def __enter__(self): return self
            def __exit__(self, *_): pass
        class Camera:
            def __init__(self): self.start_kwargs = None; self.capture = None
            def start(self, **kwargs): self.start_kwargs = kwargs
            def get_latest_frame(self, **_):
                self.capture.stop.set()
                return np.zeros((480, 640, 4), dtype=np.uint8), 1
            def stop(self): pass
            def release(self): pass
        camera = Camera()
        capture = LatestFrameCapture(640, 360, 60, ShareStats(), window_name="Settings", window_hwnd=123)
        camera.capture = capture
        def window_rect(_hwnd, pointer):
            pointer._obj.left, pointer._obj.top = 100, 100
            pointer._obj.right, pointer._obj.bottom = 740, 580
            return True
        fake_dxcam = mock.Mock()
        fake_dxcam.create.return_value = camera
        with mock.patch("wire_webrtc.mss.mss", return_value=Desktop()), \
             mock.patch("wire_webrtc.dxcam", fake_dxcam), \
             mock.patch("wire_webrtc.ctypes.windll", create=True) as windll:
            windll.user32.GetWindowRect.side_effect = window_rect
            capture._run_dxcam()
        self.assertTrue(camera.start_kwargs["video_mode"])
        self.assertEqual(camera.start_kwargs["region"], (100, 100, 740, 580))
        self.assertIsNotNone(capture.latest())


if __name__ == "__main__":
    unittest.main()
