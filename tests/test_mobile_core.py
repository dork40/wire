import os
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


if __name__ == "__main__":
    unittest.main()
