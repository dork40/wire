import asyncio
import unittest

from av import VideoFrame

from wire_webrtc import ScreenTrack, ShareStats


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


if __name__ == "__main__":
    unittest.main()
