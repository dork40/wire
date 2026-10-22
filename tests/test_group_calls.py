import time
import unittest

import wire
from test_group_files import TwoClientHarness
from test_security_fixes import ServerHarness

try:
    import numpy
except ImportError:  # the media extra isn't installed
    numpy = None


class FakeAudio:
    """sounddevice / pynput / WebRTC audio processing stand-ins."""

    def __init__(self) -> None:
        self.opened_microphones = 0
        self.played: list[bytes] = []
        audio = self

        class RawInputStream:
            def __init__(self, **kwargs):
                audio.opened_microphones += 1

            def start(self): pass
            def stop(self): pass
            def close(self): pass

        class RawOutputStream:
            def __init__(self, **kwargs): pass
            def start(self): pass
            def stop(self): pass
            def close(self): pass

            def write(self, data):
                audio.played.append(bytes(data))
                time.sleep(0.02)

        class Listener:
            def __init__(self, **kwargs): pass
            def start(self): pass
            def stop(self): pass
            def close(self): pass

        class Keyboard:
            Key = type("Key", (), {"f12": "f12"})

        Keyboard.Listener = Listener

        class Processor:
            def __init__(self, **kwargs): pass

            def process(self, near, far):
                return near

        self.sd = type("SD", (), {"RawInputStream": RawInputStream, "RawOutputStream": RawOutputStream})
        self.keyboard, self.processor = Keyboard, Processor


def frame(value: int) -> bytes:
    return numpy.full(wire.GroupVoiceCall.FRAME_SAMPLES, value, dtype=numpy.int16).tobytes()


@unittest.skipIf(numpy is None, "numpy is part of the media extra")
class FakeAudioMixin:
    def install_fake_audio(self) -> FakeAudio:
        self._saved_audio = (wire.sd, wire.keyboard, wire.np, wire.AudioProcessor)
        fake = FakeAudio()
        wire.sd, wire.keyboard, wire.np, wire.AudioProcessor = fake.sd, fake.keyboard, numpy, fake.processor
        return fake

    def restore_audio(self) -> None:
        wire.sd, wire.keyboard, wire.np, wire.AudioProcessor = self._saved_audio


@unittest.skipIf(numpy is None, "numpy is part of the media extra")
class MixerTests(FakeAudioMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.fake = self.install_fake_audio()
        self.call = wire.GroupVoiceCall("crew", "a" * 16, {"voice_mode": "open"})
        self.call.running.clear()  # drive the mixer by hand
        for name in ("bob", "carol"):
            self.call.add(wire.Peer(name, None, b"k" * 32, b"p" * 32))

    def tearDown(self) -> None:
        self.call.close()
        self.restore_audio()

    def test_everyone_is_added_together_and_clipped(self):
        self.call.receive("bob", frame(1000))
        self.call.receive("carol", frame(500))
        mixed = numpy.frombuffer(self.call.mix_next(), dtype=numpy.int16)
        self.assertTrue((mixed == 1500).all())
        self.call.receive("bob", frame(30000))
        self.call.receive("carol", frame(30000))
        self.assertTrue((numpy.frombuffer(self.call.mix_next(), dtype=numpy.int16) == 32767).all())
        self.assertIsNone(self.call.mix_next())

    def test_strangers_and_bad_frames_are_ignored(self):
        self.call.receive("mallory", frame(1))
        self.call.receive("bob", b"short")
        self.assertIsNone(self.call.mix_next())

    def test_a_backlog_is_capped_not_played_late(self):
        for value in range(20):
            self.call.receive("bob", frame(value))
        self.assertEqual(len(self.call.queues["bob"]), wire.GroupVoiceCall.MAX_QUEUED_FRAMES)


@unittest.skipIf(numpy is None, "numpy is part of the media extra")
class GroupCallSignallingTests(FakeAudioMixin, TwoClientHarness):
    def setUp(self) -> None:
        self.fake = self.install_fake_audio()
        super().setUp()

    def tearDown(self) -> None:
        for app in self.apps.values():
            if app.group_call:
                app.group_call.close()
        super().tearDown()
        self.restore_audio()

    def test_ring_join_talk_and_leave(self):
        alice, bob = self.apps["alice"], self.apps["bob"]
        alice.group_room = "crew"
        wire.run_command(alice, "call", "")
        self.assertEqual(self.fake.opened_microphones, 1)  # only the caller's

        self.wait_for(lambda: "crew" in bob.group_call_invites)
        self.assertIsNone(bob.group_call)  # being rung never opens your microphone
        self.assertEqual(self.fake.opened_microphones, 1)

        wire.run_command(bob, "joincall", "crew")
        self.wait_for(lambda: "bob" in alice.group_call.participants and "alice" in bob.group_call.participants)

        alice.group_call.send_frame(frame(1234))
        self.wait_for(lambda: any(numpy.frombuffer(chunk, dtype=numpy.int16)[0] == 1234 for chunk in self.fake.played))

        wire.run_command(bob, "hangup", "")
        self.assertIsNone(bob.group_call)
        self.wait_for(lambda: "bob" not in alice.group_call.participants)

    def test_audio_is_ignored_until_you_join(self):
        alice, bob = self.apps["alice"], self.apps["bob"]
        alice.group_room = "crew"
        wire.run_command(alice, "call", "")
        self.wait_for(lambda: "crew" in bob.group_call_invites)
        alice.group_call.add(alice.member_peer("bob"))  # a pushy caller sends anyway
        alice.group_call.send_frame(frame(99))
        time.sleep(0.4)
        self.assertEqual(self.fake.played, [])


class LiveAudioIsNeverQueuedTests(unittest.TestCase):
    def test_audio_to_an_offline_person_is_dropped_not_queued(self):
        harness = ServerHarness()
        try:
            server = harness.server
            alice = harness.login("alice")
            users = server.load_users()
            users["bob"] = {"name": "bob"}
            server.save_users(users)
            server.send(alice, {"type": "relay", "to": "bob", "packet": {"type": "audio", "nonce": "x", "data": "y"}})
            server.send(alice, {"type": "relay", "to": "bob", "packet": {"type": "msg", "nonce": "x", "data": "y"}})
            server.send(alice, {"type": "ping", "id": "done"})
            self.assertEqual(server.receive(alice)["type"], "pong")
            queued = server.load_queues().get("bob", [])
            self.assertEqual([item["packet"]["type"] for item in queued], ["msg"])
        finally:
            harness.close()


if __name__ == "__main__":
    unittest.main()
