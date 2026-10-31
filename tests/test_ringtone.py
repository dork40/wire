import time
import unittest

import wire
from test_account_features import TempAccount


class FakeSpeaker:
    def __init__(self) -> None:
        self.written = 0
        speaker = self

        class RawOutputStream:
            def __init__(self, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *exc): return False

            def write(self, data):
                speaker.written += len(data)
                time.sleep(0.01)

        self.RawOutputStream = RawOutputStream


class RingtoneTests(TempAccount):
    def setUp(self) -> None:
        super().setUp()
        self.old_sd, self.speaker = wire.sd, FakeSpeaker()
        wire.sd = self.speaker

    def tearDown(self) -> None:
        self.app.ringer.stop_all()
        wire.sd = self.old_sd
        super().tearDown()

    def test_ring_cycle_is_valid_audio(self):
        cycle = wire.ring_cycle()
        self.assertEqual(len(cycle), int(wire.RING_RATE * 3.0) * 2)

    def test_rings_until_answered(self):
        self.app.ring("bob", "bob")
        time.sleep(0.2)
        self.assertGreater(self.speaker.written, 0)
        self.app.ringer.stop("bob")
        time.sleep(0.1)
        written = self.speaker.written
        time.sleep(0.2)
        self.assertEqual(self.speaker.written, written)  # stopped

    def test_silent_when_muted_or_do_not_disturb(self):
        wire.run_command(self.app, "mute", "bob")
        self.app.ring("bob", "bob")
        self.app.settings["do_not_disturb"] = True
        self.app.ring("carol", "carol")
        time.sleep(0.2)
        self.assertEqual(self.speaker.written, 0)


if __name__ == "__main__":
    unittest.main()
