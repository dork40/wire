import os
import sys
import types
import unittest
from pathlib import Path

import wire


class MobileCoreTests(unittest.TestCase):
    """Chat, friends, and encrypted files must survive a missing media stack.

    Phone terminals (Termux on Android, for example) cannot always install
    aiortc/PyAV/portaudio-backed packages. wire.py imports that whole stack
    through a single guarded block; these tests pin down the fallback
    behaviour instead of letting it silently regress into a startup crash.
    """

    def test_media_available_flag_matches_webrtcshare(self):
        self.assertEqual(wire.MEDIA_AVAILABLE, wire.WebRTCShare is not None)

    def test_start_share_without_media_reports_clear_error(self):
        app = wire.Wire()
        peer = wire.Peer("alice", None, os.urandom(32), os.urandom(32))
        old = wire.WebRTCShare
        wire.WebRTCShare = None
        try:
            with self.assertRaises(ValueError) as failure:
                app.start_share(peer)
            self.assertIn("not installed on this device", str(failure.exception))
        finally:
            wire.WebRTCShare = old

    def test_answer_share_offer_accept_without_media_keeps_offer_pending(self):
        app = wire.Wire()
        app.peers["alice"] = wire.Peer("alice", None, os.urandom(32), os.urandom(32))
        share_id = "a" * 32
        state = {"from": "alice", "offer": {"id": share_id, "sdp": "x", "resolution": [1280, 720], "fps": 30}}
        app.pending_shares[share_id] = state
        old = wire.WebRTCShare
        wire.WebRTCShare = None
        try:
            with self.assertRaises(ValueError) as failure:
                app.answer_share_offer(share_id[:6], True)
            self.assertIn("not installed on this device", str(failure.exception))
            # A rejected-for-missing-media offer is not the same as a decline;
            # the person could still accept it later from a desktop client.
            self.assertIn(share_id, app.pending_shares)
        finally:
            wire.WebRTCShare = old

    def test_voice_call_without_media_reports_clear_error_not_a_crash(self):
        peer = wire.Peer("alice", None, os.urandom(32), os.urandom(32))
        old_np, old_processor = wire.np, wire.AudioProcessor
        wire.np = None
        wire.AudioProcessor = None
        try:
            with self.assertRaises(ValueError) as failure:
                wire.VoiceCall(peer, {})
            self.assertIn("not installed on this device", str(failure.exception))
        finally:
            wire.np, wire.AudioProcessor = old_np, old_processor

    def test_network_diagnose_without_media_does_not_crash(self):
        app = wire.Wire()
        old, lines = wire.network_diagnostics, []
        wire.network_diagnostics = None
        wire.say = lines.append
        try:
            app.diagnose(network=True)
        finally:
            wire.network_diagnostics = old
        self.assertTrue(any("not installed on this device" in line for line in lines))

    def test_installers_install_the_optional_media_extra_on_desktop(self):
        root = Path(wire.__file__).parent
        windows_ps1 = (root / "install-wire.ps1").read_text(encoding="utf-8")
        windows_cmd = (root / "install-wire.cmd").read_text(encoding="utf-8")
        linux_sh = (root / "install-wire.sh").read_text(encoding="utf-8")
        self.assertIn("wire-messenger[media]", windows_ps1)
        self.assertIn("wire-messenger[media]", windows_cmd)
        self.assertIn("wire-messenger[media]", linux_sh)
        # Termux has no sudo and cannot build aiortc/PyAV; it must install the
        # plain chat-only path instead of the generic apt/dnf/pacman branch.
        self.assertIn("TERMUX_VERSION", linux_sh)
        self.assertIn('python -m pipx install --force "$SOURCE"', linux_sh)


class HeadlessFrontendTests(unittest.TestCase):
    """A non-terminal frontend (the Android app) drives signup/login and
    commands without getpass or prompt_toolkit's REPL loop.
    """

    def test_signup_accepts_a_password_argument_without_getpass(self):
        app = wire.Wire()
        old_load, old_save = wire.load_users, wire.save_users
        saved = {}
        wire.load_users = lambda: {}
        wire.save_users = lambda users: saved.update(users)
        old_getpass = wire.getpass.getpass
        wire.getpass.getpass = lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("should not prompt"))
        try:
            app.signup("mobiletester", password="correct horse battery staple")
        finally:
            wire.load_users, wire.save_users = old_load, old_save
            wire.getpass.getpass = old_getpass
        self.assertIn("mobiletester", saved)

    def test_login_accepts_a_password_argument_without_getpass(self):
        app = wire.Wire()
        real = wire.Wire()
        old_load, old_save = wire.load_users, wire.save_users
        saved = {}
        wire.load_users = lambda: {}
        wire.save_users = lambda users: saved.update(users)
        try:
            real.signup("mobilelogin", password="correct horse battery staple")
        finally:
            wire.load_users, wire.save_users = old_load, old_save
        account = saved["mobilelogin"]
        wire.load_users = lambda: {"mobilelogin": account}
        app.connect_server = lambda *a, **k: None
        old_getpass = wire.getpass.getpass
        wire.getpass.getpass = lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("should not prompt"))
        try:
            app.login("mobilelogin", password="correct horse battery staple")
        finally:
            wire.load_users = old_load
            wire.getpass.getpass = old_getpass
        self.assertEqual(app.name, "mobilelogin")

    def test_run_command_quit_and_settings_delete_stop_the_session(self):
        app = wire.Wire()
        wire.say = lambda _line: None
        self.assertFalse(wire.run_command(app, "quit", ""))
        app.delete_account = lambda: None
        self.assertFalse(wire.run_command(app, "settings", "delete"))

    def test_run_command_server_stats_does_not_raise(self):
        app = wire.Wire()
        sent = []
        app.server_send = sent.append
        self.assertTrue(wire.run_command(app, "server", "stats"))
        self.assertEqual(sent, [{"type": "server_stats"}])

    def test_handle_input_routes_plain_text_to_the_open_room(self):
        app = wire.Wire()
        peer = wire.Peer("alice", None, os.urandom(32), os.urandom(32))
        app.peers["alice"] = peer
        app.room = "alice"
        sent = []
        app.send_message = lambda target, text: sent.append((target.name, text))
        self.assertTrue(wire.handle_input(app, "hello there"))
        self.assertEqual(sent, [("alice", "hello there")])


class AndroidDownloadsDirTests(unittest.TestCase):
    """DOWNLOADS_DIR must never crash computing itself, and on Android must
    prefer the file-manager-visible external storage over the private
    sandbox Path.home() resolves to there (see _android_downloads_dir's own
    docstring for why that distinction matters for received files).
    """

    def setUp(self):
        self._had_android_argument = "ANDROID_ARGUMENT" in os.environ
        self._old_android_argument = os.environ.get("ANDROID_ARGUMENT")
        self._old_jnius = sys.modules.get("jnius")

    def tearDown(self):
        if self._had_android_argument:
            os.environ["ANDROID_ARGUMENT"] = self._old_android_argument
        else:
            os.environ.pop("ANDROID_ARGUMENT", None)
        if self._old_jnius is not None:
            sys.modules["jnius"] = self._old_jnius
        else:
            sys.modules.pop("jnius", None)

    def test_desktop_without_android_argument_returns_none(self):
        os.environ.pop("ANDROID_ARGUMENT", None)
        self.assertIsNone(wire._android_downloads_dir())

    def test_android_without_jnius_falls_back_safely(self):
        os.environ["ANDROID_ARGUMENT"] = "1"
        sys.modules.pop("jnius", None)  # not installed outside an Android build
        self.assertIsNone(wire._android_downloads_dir())

    def test_android_with_jnius_uses_external_files_dir(self):
        os.environ["ANDROID_ARGUMENT"] = "1"

        class FakeFile:
            def getAbsolutePath(self):
                return "/storage/emulated/0/Android/data/net.dork40.wire/files/Download"

        class FakeActivity:
            def getExternalFilesDir(self, kind):
                assert kind == "DOWNLOAD_TYPE"
                return FakeFile()

        class FakePythonActivity:
            mActivity = FakeActivity()

        class FakeEnvironment:
            DIRECTORY_DOWNLOADS = "DOWNLOAD_TYPE"

        def fake_autoclass(name):
            return {"org.kivy.android.PythonActivity": FakePythonActivity,
                    "android.os.Environment": FakeEnvironment}[name]

        fake_jnius = types.ModuleType("jnius")
        fake_jnius.autoclass = fake_autoclass
        sys.modules["jnius"] = fake_jnius

        result = wire._android_downloads_dir()
        self.assertEqual(result, Path("/storage/emulated/0/Android/data/net.dork40.wire/files/Download"))

    def test_android_with_broken_jnius_falls_back_safely(self):
        os.environ["ANDROID_ARGUMENT"] = "1"
        fake_jnius = types.ModuleType("jnius")
        fake_jnius.autoclass = lambda name: (_ for _ in ()).throw(RuntimeError("no activity yet"))
        sys.modules["jnius"] = fake_jnius
        self.assertIsNone(wire._android_downloads_dir())


class AndroidDataDirTests(unittest.TestCase):
    """DATA (identity keys, directory-keys.json, settings, history) must
    resolve to the app's actual writable sandbox on Android, not
    Path.home() - confirmed on a real device that it returns '/data', a
    privileged directory no regular app can write to. Every local write,
    starting with pinning the directory's TLS key on the very first
    connection, failed with PermissionError until this was fixed; both
    test accounts could reach the server and decrypt their recovered
    identity correctly but still failed login identically because of it.
    """

    def setUp(self):
        self._had_android_argument = "ANDROID_ARGUMENT" in os.environ
        self._old_android_argument = os.environ.get("ANDROID_ARGUMENT")
        self._old_jnius = sys.modules.get("jnius")

    def tearDown(self):
        if self._had_android_argument:
            os.environ["ANDROID_ARGUMENT"] = self._old_android_argument
        else:
            os.environ.pop("ANDROID_ARGUMENT", None)
        if self._old_jnius is not None:
            sys.modules["jnius"] = self._old_jnius
        else:
            sys.modules.pop("jnius", None)

    def test_desktop_without_android_argument_returns_none(self):
        os.environ.pop("ANDROID_ARGUMENT", None)
        self.assertIsNone(wire._android_data_dir())

    def test_android_without_jnius_falls_back_safely(self):
        os.environ["ANDROID_ARGUMENT"] = "1"
        sys.modules.pop("jnius", None)
        self.assertIsNone(wire._android_data_dir())

    def test_android_with_jnius_uses_get_files_dir(self):
        os.environ["ANDROID_ARGUMENT"] = "1"

        class FakeFile:
            def getAbsolutePath(self):
                return "/data/user/0/net.dork40.wire/files"

        class FakeActivity:
            def getFilesDir(self):
                return FakeFile()

        class FakePythonActivity:
            mActivity = FakeActivity()

        def fake_autoclass(name):
            assert name == "org.kivy.android.PythonActivity"
            return FakePythonActivity

        fake_jnius = types.ModuleType("jnius")
        fake_jnius.autoclass = fake_autoclass
        sys.modules["jnius"] = fake_jnius

        result = wire._android_data_dir()
        self.assertEqual(result, Path("/data/user/0/net.dork40.wire/files"))

    def test_android_with_broken_jnius_falls_back_safely(self):
        os.environ["ANDROID_ARGUMENT"] = "1"
        fake_jnius = types.ModuleType("jnius")
        fake_jnius.autoclass = lambda name: (_ for _ in ()).throw(RuntimeError("no activity yet"))
        sys.modules["jnius"] = fake_jnius
        self.assertIsNone(wire._android_data_dir())


if __name__ == "__main__":
    unittest.main()
