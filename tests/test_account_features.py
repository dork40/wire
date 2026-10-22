import json
import tempfile
import unittest
from pathlib import Path

import wire


class TempAccount(unittest.TestCase):
    """A real signed-up, logged-in account whose files live in a temp dir."""

    PASSWORD = "correct horse battery"

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        root = Path(self._temp.name)
        names = ("USERS", "HISTORY_DIR", "CONTACTS_DIR", "SETTINGS_FILE", "DOWNLOADS_DIR", "RATCHET_DIR", "TRANSFER_TEMP_DIR")
        self._saved = {name: getattr(wire, name) for name in names}
        wire.USERS = root / "users.json"
        wire.HISTORY_DIR = root / "history"
        wire.CONTACTS_DIR = root / "contacts"
        wire.SETTINGS_FILE = root / "settings.json"
        wire.DOWNLOADS_DIR = root / "Downloads"
        wire.RATCHET_DIR = root / "ratchets"
        wire.TRANSFER_TEMP_DIR = root / "transfer-temp"
        self._old_say = wire.say
        self.lines: list[str] = []
        wire.say = self.lines.append
        wire.Wire().signup("tester", password=self.PASSWORD)
        self.app = self.login(self.PASSWORD)

    def tearDown(self) -> None:
        wire.say = self._old_say
        for name, value in self._saved.items():
            setattr(wire, name, value)
        self._temp.cleanup()

    def login(self, password: str) -> wire.Wire:
        app = wire.Wire()
        app.connect_server = lambda *args, **kwargs: None
        app.login("tester", password=password)
        return app


class MuteTests(TempAccount):
    def test_muted_people_and_groups_stay_silent(self):
        self.assertTrue(self.app.notifications_allowed("bob"))
        wire.run_command(self.app, "mute", "Bob")
        wire.run_command(self.app, "mute", "group crew")
        self.assertFalse(self.app.notifications_allowed("bob"))
        self.assertFalse(self.app.notifications_allowed("group-crew"))
        self.assertTrue(self.app.notifications_allowed("carol"))
        wire.run_command(self.app, "unmute", "bob")
        self.assertTrue(self.app.notifications_allowed("bob"))

    def test_mute_list_survives_a_restart(self):
        wire.run_command(self.app, "mute", "bob")
        self.assertEqual(wire.load_settings()["muted"], ["bob"])

    def test_bad_names_are_rejected(self):
        self.lines.clear()
        wire.run_command(self.app, "mute", "../../etc")
        self.assertTrue(any(line.startswith("error:") for line in self.lines) or self.app.settings["muted"] == [])
        self.assertEqual(self.app.settings["muted"], [])


class ExportTests(TempAccount):
    def test_export_writes_readable_history(self):
        self.app.record_history("bob", "bob", "see you at 8")
        self.app.record_history("bob", "tester", "on my way")
        path = self.app.export_history("bob")
        text = path.read_text(encoding="utf-8")
        self.assertIn("bob > see you at 8", text)
        self.assertIn("tester > on my way", text)
        self.assertEqual(path.parent, wire.DOWNLOADS_DIR / "Wire exports")

    def test_group_export_and_empty_chat(self):
        self.app.record_history("group-crew", "carol", "hi all")
        self.assertIn("carol > hi all", self.app.export_history("group crew").read_text(encoding="utf-8"))
        with self.assertRaises(ValueError):
            self.app.export_history("nobody")


class HistoryNameTests(TempAccount):
    def test_history_files_cannot_escape_the_history_folder(self):
        with self.assertRaises(ValueError):
            self.app.history_path("../../outside")
        self.assertEqual(self.app.read_history("../../outside"), [])

    def test_group_message_with_hostile_group_name_is_ignored(self):
        self.app.handle_group_message({"group": "../../evil", "from": "x", "public": "p", "sign_public": "s",
                                       "identity_signature": "i", "packet": {"type": "msg"}})
        self.assertFalse(any(wire.HISTORY_DIR.parent.glob("*evil*")))


class PasswordChangeTests(TempAccount):
    NEW = "a much longer passphrase"

    def test_short_passwords_are_refused_for_new_accounts_and_changes(self):
        with self.assertRaises(ValueError):
            wire.Wire().signup("shorty", password="1233")
        with self.assertRaises(ValueError):
            self.app.change_password(self.PASSWORD, "1234567")

    def test_wrong_current_password_changes_nothing(self):
        before = wire.USERS.read_bytes()
        with self.assertRaises(ValueError):
            self.app.change_password("not my password", self.NEW)
        self.assertEqual(wire.USERS.read_bytes(), before)

    def test_change_rekeys_identity_history_and_contacts(self):
        self.app.record_history("bob", "bob", "secret plans")
        contacts = self.app.contacts()
        contacts["blocked"] = ["mallory"]
        self.app.save_contacts(contacts)
        public_before = self.app.public

        self.app.change_password(self.PASSWORD, self.NEW)

        with self.assertRaises(ValueError):
            self.login(self.PASSWORD)
        fresh = self.login(self.NEW)
        self.assertEqual(fresh.public, public_before)  # same identity, new password
        self.assertEqual(fresh.read_history("bob")[-1]["text"], "secret plans")
        self.assertTrue(fresh.is_blocked("mallory"))
        # The running session keeps working without logging in again.
        self.app.record_history("bob", "tester", "still works")
        self.assertEqual(fresh.read_history("bob")[-1]["text"], "still works")

    def test_login_warns_about_short_existing_passwords(self):
        account = json.loads(wire.USERS.read_text(encoding="utf-8"))
        self.assertIn("tester", account)
        self.lines.clear()
        old_minimum = wire.MIN_PASSWORD_CHARS
        wire.MIN_PASSWORD_CHARS = 100
        try:
            self.login(self.PASSWORD)
        finally:
            wire.MIN_PASSWORD_CHARS = old_minimum
        self.assertTrue(any("use /password" in line for line in self.lines))


class FakePeer:
    def __init__(self, name: str = "bob") -> None:
        self.name = name
        self.controls: list[dict] = []

    def send_control(self, control: dict) -> None:
        self.controls.append(control)


class DisappearingMessageTests(TempAccount):
    def test_timer_is_stored_announced_and_applied_to_new_messages(self):
        peer = FakePeer()
        self.app.set_chat_timer(peer, "1h")
        self.assertEqual(peer.controls, [{"kind": "chat_timer", "seconds": 3600}])
        self.assertEqual(wire.load_settings()["timers"], {"bob": 3600})
        self.app.record_history("bob", "bob", "self destructs")
        record = self.app.read_history("bob")[-1]
        self.assertAlmostEqual(record["expires_at"], wire.time.time() + 3600, delta=5)
        self.app.set_chat_timer(peer, "off")
        self.app.record_history("bob", "bob", "stays")
        self.assertNotIn("expires_at", self.app.read_history("bob")[-1])

    def test_expired_messages_are_hidden_then_purged_everywhere(self):
        self.app.record_history("bob", "bob", "keep me")
        self.app.record_history("bob", "bob", "gone soon")
        records = self.app.read_history("bob")
        records[-1]["expires_at"] = int(wire.time.time()) - 1
        self.app.save_history("bob", records)
        self.assertEqual([r["text"] for r in self.app.read_history("bob")], ["keep me"])
        self.assertEqual(len(self.app.read_history("bob", include_expired=True)), 2)

        sent = []
        self.app.server = object()
        self.app.server_send = sent.append
        self.app.server_version = "1.4.36"
        self.assertEqual(self.app.purge_expired(), 1)
        self.assertEqual(len(self.app.read_history("bob", include_expired=True)), 1)
        self.assertEqual([p["type"] for p in sent], ["sync_delete_message"])

    def test_old_servers_are_not_sent_the_new_delete_command(self):
        self.app.record_history("bob", "bob", "gone")
        records = self.app.read_history("bob")
        records[-1]["expires_at"] = 1
        self.app.save_history("bob", records)
        sent = []
        self.app.server = object()
        self.app.server_send = sent.append
        self.app.server_version = "1.4.35"
        self.assertEqual(self.app.purge_expired(), 1)
        self.assertEqual(sent, [])

    def test_bad_timer_values_are_refused(self):
        with self.assertRaises(ValueError):
            self.app.set_chat_timer(FakePeer(), "3 days")


class RemoteInputTests(TempAccount):
    def test_reaction_cannot_carry_terminal_commands(self):
        self.app.record_history("bob", "tester", "hello")
        message_id = self.app.read_history("bob")[-1]["id"]
        self.lines.clear()
        self.app.apply_message_control(FakePeer(), {"kind": "message_react", "id": message_id, "reaction": "\x1b[2J\x1b]52;c;eA==\x07"})
        self.assertTrue(all("\x1b" not in line and "\x07" not in line for line in self.lines))
        self.app.apply_message_control(FakePeer(), {"kind": "message_react", "id": message_id, "reaction": "\x1b\x07"})
        self.assertEqual(len(self.app.read_history("bob")[-1]["reactions"]), 1)

    def test_direct_connections_respect_username_rules_and_blocks(self):
        other = wire.Wire()
        other.connect_server = lambda *args, **kwargs: None
        wire.Wire().signup("mallory", password="another long password")
        other.login("mallory", password="another long password")
        contacts = self.app.contacts()
        contacts["blocked"] = ["mallory"]
        self.app.save_contacts(contacts)
        with self.assertRaisesRegex(ValueError, "blocked"):
            self.app.make_peer(None, other.hello())
        hello = other.hello()
        hello["name"] = "../../evil"
        with self.assertRaisesRegex(ValueError, "username"):
            self.app.make_peer(None, hello)

    @unittest.skipUnless(wire.os.name == "nt", "pop-ups are Windows-only")
    def test_notification_bursts_start_one_process_not_hundreds(self):
        started = []
        old_popen, old_foreground = wire.subprocess.Popen, wire.wire_console_is_foreground
        wire.subprocess.Popen = lambda *args, **kwargs: started.append(args)
        wire.wire_console_is_foreground = lambda: False
        wire._last_toast_at = float("-inf")
        try:
            for _ in range(200):
                wire.toast("new message from spammer")
        finally:
            wire.subprocess.Popen, wire.wire_console_is_foreground = old_popen, old_foreground
        self.assertEqual(len(started), 1)


class VoiceCallConsentTests(TempAccount):
    @staticmethod
    def voice_packet(key: bytes, frame: dict) -> dict:
        nonce = wire.os.urandom(12)
        data = wire.AESGCM(key).encrypt(nonce, json.dumps(frame).encode("utf-8"), b"wire-v1-voice")
        return {"type": "voice", "nonce": wire.b64(nonce), "data": wire.b64(data)}

    def test_unrequested_accept_does_not_open_the_microphone(self):
        started = []
        self.app.start_call = lambda peer: started.append(peer.name)
        peer = wire.Peer("mallory", None, wire.os.urandom(32), wire.os.urandom(32))
        self.app.handle_voice(peer, self.voice_packet(peer.key, {"kind": "accept"}))
        self.assertEqual(started, [])

    def test_accept_after_we_called_starts_the_call_once(self):
        started = []
        self.app.start_call = lambda peer: started.append(peer.name)
        peer = wire.Peer("bob", None, wire.os.urandom(32), wire.os.urandom(32))
        peer.send_voice_frame = lambda frame: None
        self.app.request_call(peer)
        self.app.handle_voice(peer, self.voice_packet(peer.key, {"kind": "accept"}))
        self.app.handle_voice(peer, self.voice_packet(peer.key, {"kind": "accept"}))  # replayed
        self.assertEqual(started, ["bob"])


class AccountSearchTests(TempAccount):
    def test_find_sends_the_query_and_refuses_one_letter(self):
        sent = []
        self.app.server = object()
        self.app.server_send = sent.append
        wire.run_command(self.app, "find", "  bo ")
        self.assertEqual(sent, [{"type": "discover", "query": "bo"}])
        self.lines.clear()
        wire.run_command(self.app, "find", "b")
        self.assertEqual(len(sent), 1)

    def test_results_show_relationship_and_how_to_act(self):
        contacts = self.app.contacts()
        contacts["blocked"] = ["mallory"]
        self.app.save_contacts(contacts)
        self.lines.clear()
        self.app.show_search_results({"query": "o", "more": False, "users": [
            {"name": "bob", "online": True, "friend": True},
            {"name": "mallory", "online": False},
            {"name": "joe", "online": None, "request_received": True},
            {"name": "tester", "online": True, "you": True},
            {"name": "\x1b[2Jevil", "online": True},
        ]})
        text = "\n".join(self.lines)
        self.assertRegex(text, r"bob\s+\[online\]\s+friend")
        self.assertRegex(text, r"mallory\s+\[offline\]\s+blocked")
        self.assertIn("/friend accept joe", text)
        self.assertRegex(text, r"joe\s+\[hidden\]")
        self.assertRegex(text, r"tester\s+\[online\]\s+you")
        self.assertNotIn("\x1b", text)
        self.assertIn("open <name>", text)


class KeyChangeTests(TempAccount):
    def test_changed_key_is_refused_announced_once_then_trustable(self):
        old_public, old_sign = b"o" * 32, b"s" * 32
        new_public, new_sign = b"n" * 32, b"t" * 32
        self.app.verify_peer_identity("bob", old_public, old_sign)
        self.lines.clear()
        for _ in range(3):  # e.g. three group messages from the new key
            with self.assertRaisesRegex(ValueError, "identity key changed"):
                self.app.verify_peer_identity("bob", new_public, new_sign)
        self.assertEqual(sum("SAFETY WARNING" in line for line in self.lines), 1)
        self.assertTrue(any(wire.fingerprint(new_public) in line for line in self.lines))

        wire.run_command(self.app, "trust", "bob")
        self.app.verify_peer_identity("bob", new_public, new_sign)  # now accepted
        with self.assertRaises(ValueError):
            self.app.verify_peer_identity("bob", old_public, old_sign)  # and the old key is not

    def test_trust_needs_a_pending_key_change(self):
        with self.assertRaises(ValueError):
            self.app.trust_new_identity("bob")


if __name__ == "__main__":
    unittest.main()
