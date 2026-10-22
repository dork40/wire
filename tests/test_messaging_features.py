import time
import unittest

import wire
from test_account_features import FakePeer, TempAccount


class RecordingPeer(FakePeer):
    """A connected 1:1 peer whose sent messages we can inspect."""

    def __init__(self, name: str = "bob") -> None:
        super().__init__(name)
        self.sent: list[str] = []
        self.key = b"k" * 32
        self.public_key = b"p" * 32
        self.sock = None

    def send(self, text: str, message_id: str, reply_to=None) -> None:
        self.sent.append(text)


class Base(TempAccount):
    def setUp(self) -> None:
        super().setUp()
        self.bob = RecordingPeer("bob")
        self.app.peers["bob"] = self.bob
        self.group_sent: list[tuple[str, str]] = []
        self.app.send_group_message = lambda group, text: (self.group_sent.append((group, text)),
                                                           self.app.record_history(f"group-{group}", "tester", text))
        self.app.groups["crew"] = {"name": "crew", "members": []}


class ChatListTests(Base):
    def test_unread_counts_mentions_and_clearing(self):
        self.app.record_history("bob", "bob", "hey")
        self.app.room = "carol"  # looking at another chat
        self.app.note_incoming("bob")
        self.app.note_incoming("bob")
        self.app.note_incoming("group-crew", mentioned=True)
        self.lines.clear()
        self.app.show_chats()
        text = "\n".join(self.lines)
        self.assertRegex(text, r"bob\s+2 new")
        self.assertRegex(text, r"group crew\s+1 new, 1 @you")
        self.app.show_history("bob")  # opening the chat reads it
        self.assertNotIn("bob", self.app.unread)

    def test_messages_in_the_open_chat_are_not_unread(self):
        self.app.room = "bob"
        self.app.note_incoming("bob")
        self.assertEqual(self.app.unread, {})

    def test_mentions_match_whole_names_only(self):
        self.assertTrue(self.app.is_mentioned("hey @Tester look"))
        self.assertFalse(self.app.is_mentioned("hey @testers"))
        self.assertFalse(self.app.is_mentioned("email tester@example.com"))


class PollTests(Base):
    def test_poll_vote_and_results_in_a_room(self):
        self.app.room = "bob"
        wire.run_command(self.app, "poll", "Lunch? | pizza | tacos | sushi")
        poll = self.bob.sent[-1]
        code, question, options = wire.parse_poll(poll)
        self.assertEqual((question, options), ("Lunch?", ["pizza", "tacos", "sushi"]))
        self.app.record_history("bob", "bob", f"VOTE {code} 2")
        self.app.record_history("bob", "carol", f"VOTE {code} 1")
        self.app.record_history("bob", "bob", f"VOTE {code} 3")  # bob changed his mind
        wire.run_command(self.app, "vote", f"{code} 3")
        self.assertEqual(self.bob.sent[-1], f"VOTE {code} 3")
        summary = self.app.describe_poll("bob", code, detailed=True)
        self.assertIn("3 votes", summary)
        self.assertIn("sushi: 2  (bob, tester)", summary)
        self.assertIn("pizza: 1  (carol)", summary)

    def test_bad_polls_and_votes_are_refused(self):
        self.app.room = "bob"
        with self.assertRaises(ValueError):
            self.app.create_poll("Only one option | yes")
        with self.assertRaises(ValueError):
            self.app.vote("abcdef 1")  # no such poll

    def test_votes_render_readably_in_history(self):
        line = self.app.render_record({"from": "bob", "text": "VOTE abc123 2"})
        self.assertEqual(line, "bob > (voted 2 in poll abc123)")


class ForwardTests(Base):
    def test_forward_to_group_and_person(self):
        self.app.record_history("bob", "bob", "the plan is at 8")
        code = self.app.read_history("bob")[-1]["id"][:6]
        self.app.room = "bob"
        wire.run_command(self.app, "forward", f"{code} group crew")
        self.assertEqual(self.group_sent[-1], ("crew", "[forwarded from bob] the plan is at 8"))
        wire.run_command(self.app, "forward", f"{code} bob")
        self.assertEqual(self.bob.sent[-1], "[forwarded from bob] the plan is at 8")


class FormattingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old = wire.TEXT_FORMATTING
        wire.TEXT_FORMATTING = True

    def tearDown(self) -> None:
        wire.TEXT_FORMATTING = self.old

    def test_bold_italic_code(self):
        out = wire.format_text("**big** *lean* `x = 1` and_snake_case")
        self.assertIn("\x1b[1mbig\x1b[22m", out)
        self.assertIn("\x1b[3mlean\x1b[23m", out)
        self.assertIn("\x1b[36mx = 1\x1b[39m", out)
        self.assertIn("and_snake_case", out)

    def test_off_when_not_a_terminal(self):
        wire.TEXT_FORMATTING = False
        self.assertEqual(wire.format_text("**big**"), "**big**")


class ScheduleTests(Base):
    def test_parse_when(self):
        now = time.mktime((2026, 10, 22, 17, 0, 0, 0, 0, -1))
        self.assertEqual(wire.parse_when("10m", now), now + 600)
        self.assertEqual(wire.parse_when("18:30", now), now + 5400)
        self.assertEqual(wire.parse_when("16:00", now), now + 23 * 3600)  # tomorrow
        for bad in ("8d", "soon", "25:00"):
            with self.assertRaises(ValueError):
                wire.parse_when(bad, now)

    def test_twelve_hour_times(self):
        self.assertEqual([wire.twelve_hour(h, 5) for h in (0, 9, 12, 18, 23)],
                         ["12:05 AM", "9:05 AM", "12:05 PM", "6:05 PM", "11:05 PM"])
        self.assertEqual(wire.stamp_text("2026-10-22 18:04"), "2026-10-22 6:04 PM")
        self.assertEqual(wire.short_stamp("2026-10-22 00:30", "2026-10-22"), "12:30 AM")
        self.assertEqual(wire.short_stamp("2026-10-21 18:04", "2026-10-22"), "Oct 21")

    def test_history_lines_show_12_hour_times(self):
        today = time.strftime("%Y-%m-%d")
        line = self.app.render_record({"from": "bob", "text": "hi", "at": f"{today} 18:04"}, with_time=True)
        self.assertEqual(line, "[6:04 PM] bob > hi")
        older = self.app.render_record({"from": "bob", "text": "hi", "at": "2026-01-05 09:15"}, with_time=True)
        self.assertEqual(older, "[Jan 5 9:15 AM] bob > hi")
        self.assertEqual(self.app.render_record({"from": "bob", "text": "hi", "at": f"{today} 18:04"}), "bob > hi")

    def test_schedule_accepts_am_pm(self):
        now = time.mktime((2026, 10, 22, 17, 0, 0, 0, 0, -1))
        self.assertEqual(wire.parse_when("6:30pm", now), now + 5400)
        self.assertEqual(wire.parse_when("6:30 p.m.", now), now + 5400)
        self.assertEqual(wire.parse_when("12am", now), now + 7 * 3600)       # midnight
        self.assertEqual(wire.parse_when("9am", now), now + 16 * 3600)       # tomorrow morning
        with self.assertRaises(ValueError):
            wire.parse_when("13pm", now)

    def test_schedule_with_a_spaced_pm_keeps_the_message_intact(self):
        self.app.room = "bob"
        wire.run_command(self.app, "schedule", "11:59 pm see you tomorrow")
        item = self.app.scheduled[-1]
        self.assertEqual(item["text"], "see you tomorrow")
        self.lines.clear()
        self.app.show_scheduled()
        self.assertRegex("\n".join(self.lines), r"\w{3} 11:59 PM")
        wire.run_command(self.app, "unschedule", item["id"])

    def test_scheduled_message_is_sent_listed_and_cancellable(self):
        self.app.room = "bob"
        wire.run_command(self.app, "schedule", "1s good morning")
        wire.run_command(self.app, "schedule", "2h later thing")
        self.assertEqual(len(self.app.scheduled), 2)
        later = next(item for item in self.app.scheduled if item["text"] == "later thing")
        wire.run_command(self.app, "unschedule", later["id"])
        deadline = time.monotonic() + 5
        while not self.bob.sent and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.bob.sent, ["good morning"])
        self.assertEqual(self.app.scheduled, [])


class ViewOnceTests(Base):
    def test_view_once_image_never_lands_in_downloads(self):
        frames = []
        self.bob.send_image_frame = frames.append
        image = wire.DOWNLOADS_DIR.parent / "secret.png"
        from PIL import Image
        Image.new("RGB", (4, 4), "red").save(image)
        self.app.send_image(self.bob, str(image), once=True)
        self.assertTrue(frames[-1]["once"])

        offer = frames[-1]
        receiver = self.app
        receiver.pending_images[offer["id"]] = {"name": "secret.png", "size": offer["size"], "sha256": offer["sha256"], "once": True}
        peer = wire.Peer("bob", None, wire.os.urandom(32), wire.os.urandom(32))
        receiver.preview_image = lambda path: None

        def deliver(frame):
            nonce = wire.os.urandom(12)
            data = wire.AESGCM(peer.key).encrypt(nonce, wire.json.dumps(frame).encode(), b"wire-v1-image")
            receiver.handle_image(peer, {"nonce": wire.b64(nonce), "data": wire.b64(data)})

        deliver({"kind": "start", "id": offer["id"], "name": "secret.png", "size": offer["size"], "sha256": offer["sha256"]})
        deliver({"kind": "chunk", "id": offer["id"], "index": 0, "data": wire.b64(image.read_bytes())})
        deliver({"kind": "end", "id": offer["id"]})
        self.assertFalse((wire.DOWNLOADS_DIR / "secret.png").exists())
        self.assertEqual(len(receiver.view_once_files), 1)
        self.assertTrue(receiver.view_once_files[0].exists())
        receiver.close()
        self.assertFalse(receiver.view_once_files[0].exists())


class FakeSoundDevice:
    """Stands in for the sounddevice module: a microphone that produces a
    second of audio when started, and a speaker that records what it plays."""

    class CallbackStop(Exception):
        pass

    def __init__(self) -> None:
        self.played: list[tuple[int, int, bytes]] = []
        device = self

        class RawInputStream:
            def __init__(self, samplerate, channels, dtype, device=None, callback=None):
                self.callback, self.samplerate = callback, samplerate

            def start(self):
                for _ in range(10):
                    self.callback(b"\x01\x00" * (self.samplerate // 10), self.samplerate // 10, None, None)

            def stop(self):
                pass

            def close(self):
                pass

        class RawOutputStream:
            def __init__(self, samplerate, channels, dtype, device=None):
                self.samplerate, self.channels = samplerate, channels

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def write(self, frames):
                device.played.append((self.samplerate, self.channels, bytes(frames)))

        self.RawInputStream, self.RawOutputStream = RawInputStream, RawOutputStream


class VoiceMessageTests(Base):
    def setUp(self) -> None:
        super().setUp()
        self.old_sd = wire.sd
        self.fake = FakeSoundDevice()
        wire.sd = self.fake
        self.sent_files: list[str] = []
        self.app.send_file = lambda peer, path: self.sent_files.append(path)

    def tearDown(self) -> None:
        wire.sd = self.old_sd
        super().tearDown()

    def test_record_send_and_play_back(self):
        self.app.room = "bob"
        wire.run_command(self.app, "record", "")
        self.assertIsNotNone(self.app.recording)
        wire.run_command(self.app, "record", "")
        self.assertIsNone(self.app.recording)
        path = wire.Path(self.sent_files[-1])
        self.assertRegex(path.name, wire.VOICE_MESSAGE_RE)
        with wire.wave.open(str(path), "rb") as clip:
            self.assertEqual((clip.getnchannels(), clip.getframerate()), (1, wire.VOICE_SAMPLE_RATE))
            self.assertEqual(clip.getnframes(), wire.VOICE_SAMPLE_RATE)  # one second

        wire.run_command(self.app, "play", f'"{path}"')
        deadline = time.monotonic() + 5
        while not self.fake.played and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.fake.played[0][:2], (wire.VOICE_SAMPLE_RATE, 1))
        self.assertEqual(len(self.fake.played[0][2]), wire.VOICE_SAMPLE_RATE * 2)
        self.app.close()
        self.assertFalse(path.exists())  # temp recording removed on exit

    def test_group_voice_message_and_cancel(self):
        group_files = []
        self.app.send_group_file = lambda group, path: group_files.append((group, path))
        self.app.group_room = "crew"
        wire.run_command(self.app, "record", "")
        wire.run_command(self.app, "record", "cancel")
        self.assertEqual(group_files, [])
        wire.run_command(self.app, "record", "")
        wire.run_command(self.app, "record", "")
        self.assertEqual(group_files[0][0], "crew")

    def test_play_refuses_non_audio(self):
        bogus = wire.DOWNLOADS_DIR.parent / "notes.txt"
        bogus.write_text("hello")
        with self.assertRaises(ValueError):
            self.app.play_voice(str(bogus))


class LastSeenTests(Base):
    def test_friends_list_shows_last_seen_for_offline_friends(self):
        self.app.server = object()
        self.lines.clear()
        packets = iter([{"type": "friends", "users": [
            {"name": "bob", "online": False, "last_seen": int(time.time()) - 7200},
            {"name": "carol", "online": True, "last_seen": None},
        ], "requests": []}])

        def receive_once(_sock):
            packet = next(packets, None)
            if packet is None:
                raise ConnectionError("done")
            return packet

        old = wire.recv_frame
        wire.recv_frame = receive_once
        try:
            self.app.server_loop(self.app.server)
        finally:
            wire.recv_frame = old
        text = "\n".join(self.lines)
        self.assertIn("bob  [offline, last seen 2h ago]", text)
        self.assertIn("carol  [online]", text)


if __name__ == "__main__":
    unittest.main()
