import asyncio
import unittest
from unittest import mock

from av import VideoFrame

import numpy as np

from wire_webrtc import LatestFrameCapture, ScreenTrack, ShareStats, SystemAudioTrack, configure_turn, ice_configuration


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
            frame_buffer = np.zeros((16, 16, 4), dtype=np.uint8)
        class FakeCapture:
            last_kwargs = None
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                FakeCapture.last_kwargs = kwargs
                self.handlers = {}
            def event(self, callback):
                self.handlers[callback.__name__] = callback
                return callback
            def start_free_threaded(self):
                class Control:
                    def stop(self): pass
                    def wait(self): pass
                self.handlers["on_frame_arrived"](NativeFrame(), Control())
                capture.stop.set()
                return Control()
        capture = LatestFrameCapture(16, 16, 60, ShareStats(), window_name="Calculator")
        with mock.patch("wire_webrtc.WindowsCapture", FakeCapture):
            capture._run_wgc()
        self.assertEqual(capture.backend, "windows-graphics-capture")
        self.assertEqual(capture.latest()[0].width, 16)
        # Reserve time for scale/format conversion instead of adding a full
        # 17 ms WGC wait on top and unintentionally capping 60 FPS near 45.
        self.assertEqual(FakeCapture.last_kwargs["minimum_update_interval"], 7)


if __name__ == "__main__":
    unittest.main()
