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
        names = ("USERS", "HISTORY_DIR", "CONTACTS_DIR", "SETTINGS_FILE", "DOWNLOADS_DIR")
        self._saved = {name: getattr(wire, name) for name in names}
        wire.USERS = root / "users.json"
        wire.HISTORY_DIR = root / "history"
        wire.CONTACTS_DIR = root / "contacts"
        wire.SETTINGS_FILE = root / "settings.json"
        wire.DOWNLOADS_DIR = root / "Downloads"
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


if __name__ == "__main__":
    unittest.main()
