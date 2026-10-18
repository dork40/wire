import base64
import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

import wire


def load_server_module():
    path = Path(__file__).parents[1] / "wire-server.py"
    spec = importlib.util.spec_from_file_location("wire_server_sync_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EncryptedSyncTests(unittest.TestCase):
    def test_server_persists_only_opaque_sync_blobs(self):
        server = load_server_module()
        with tempfile.TemporaryDirectory() as folder:
            server.SYNC_FILE = Path(folder) / "encrypted-sync.json"
            value = {"alice": {"settings": "opaque-ciphertext", "messages": {"a" * 32: "opaque-message"}}}
            server.save_sync(value)
            self.assertEqual(server.load_sync(), value)
            self.assertNotIn("plaintext message", server.SYNC_FILE.read_text(encoding="utf-8"))

    def test_client_decrypts_and_merges_settings_and_history(self):
        with tempfile.TemporaryDirectory() as folder:
            original_settings = wire.SETTINGS_FILE
            try:
                wire.SETTINGS_FILE = Path(folder) / "settings.json"
                app = wire.Wire.__new__(wire.Wire)
                app.history_key = Fernet.generate_key()
                app.history_lock = threading.Lock()
                app.settings = wire.load_settings()
                app.server = None
                app.history_path = lambda peer: Path(folder) / f"{peer}.wire"
                remote_settings = dict(app.settings); remote_settings["notifications"] = False
                settings_blob = Fernet(app.history_key).encrypt(json.dumps({"updated": 1, "settings": remote_settings}).encode()).decode()
                record = {"id": "b" * 32, "at": "now", "from": "bob", "text": "encrypted sync works", "reactions": []}
                message_blob = Fernet(app.history_key).encrypt(json.dumps({"peer": "bob", "record": record}).encode()).decode()
                app.apply_sync_state({"settings": settings_blob, "messages": [[record["id"], message_blob]], "done": True})
                self.assertFalse(app.settings["notifications"])
                self.assertEqual(app.read_history("bob")[0]["text"], "encrypted sync works")
            finally:
                wire.SETTINGS_FILE = original_settings


if __name__ == "__main__":
    unittest.main()
