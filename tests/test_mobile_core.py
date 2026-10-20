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


if __name__ == "__main__":
    unittest.main()
