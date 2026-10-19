import base64
import importlib.util
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ed25519

import wire


def load_server_module():
    path = Path(__file__).parents[1] / "wire-server.py"
    spec = importlib.util.spec_from_file_location("wire_server_sync_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EncryptedSyncTests(unittest.TestCase):
    @staticmethod
    def authenticated_connection(server, name, public, signing):
        """Authenticate a real server handler over a socket pair."""
        client, service = socket.socketpair()
        worker = threading.Thread(target=server.handle, args=(service, ("127.0.0.1", 1)))
        worker.start()
        signing_public = base64.b64encode(signing.public_key().public_bytes_raw()).decode("ascii")
        server.send(client, {"type": "hello", "name": name, "public": public,
                             "sign_public": signing_public})
        challenge = server.receive(client)
        nonce = base64.b64decode(challenge["nonce"])
        proof = signing.sign(server.login_proof_bytes(name, nonce))
        server.send(client, {"type": "prove", "signature": base64.b64encode(proof).decode("ascii")})
        assert server.receive(client)["type"] == "ready"
        return client, worker

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

    def test_older_remote_settings_do_not_roll_back_this_device(self):
        with tempfile.TemporaryDirectory() as folder:
            original_settings = wire.SETTINGS_FILE
            try:
                wire.SETTINGS_FILE = Path(folder) / "settings.json"
                app = wire.Wire.__new__(wire.Wire)
                app.history_key = Fernet.generate_key()
                app.history_lock = threading.Lock()
                app.server = None
                app.settings = wire.load_settings()
                app.settings["notifications"] = False
                app.settings["_sync_updated"] = 200
                wire.replace_private_bytes(wire.SETTINGS_FILE, json.dumps(app.settings).encode())
                app.history_path = lambda peer: Path(folder) / f"{peer}.wire"
                stale = dict(app.settings)
                stale["notifications"] = True
                stale["_sync_updated"] = 100
                blob = Fernet(app.history_key).encrypt(
                    json.dumps({"updated": 100, "settings": stale}).encode()
                ).decode()

                app.apply_sync_state({"settings": blob, "messages": [], "done": True})

                self.assertFalse(app.settings["notifications"])
                self.assertEqual(app.settings["_sync_updated"], 200)
            finally:
                wire.SETTINGS_FILE = original_settings

    def test_second_device_fetches_and_decrypts_first_device_sync(self):
        """Exercise login, encrypted upload, persistence, reconnect, fetch, and merge."""
        server = load_server_module()
        original_paths = (server.STATE, server.USERS_FILE, server.GROUPS_FILE,
                          server.QUEUES_FILE, server.SYNC_FILE, server.BACKUPS_FILE)
        original_settings = wire.SETTINGS_FILE
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            try:
                server.STATE = root / "server"
                server.STATE.mkdir()
                server.USERS_FILE = server.STATE / "users.json"
                server.GROUPS_FILE = server.STATE / "groups.json"
                server.QUEUES_FILE = server.STATE / "offline-queue.json"
                server.SYNC_FILE = server.STATE / "encrypted-sync.json"
                server.BACKUPS_FILE = server.STATE / "identity-backups.json"
                server.ONLINE.clear()

                signing = ed25519.Ed25519PrivateKey.generate()
                public = base64.b64encode(b"i" * 32).decode("ascii")
                sign_public = base64.b64encode(signing.public_key().public_bytes_raw()).decode("ascii")
                server.save_users({"alice": {"name": "alice", "public": public,
                                               "sign_public": sign_public}})

                history_key = Fernet.generate_key()
                remote_settings = wire.load_settings()
                remote_settings["notifications"] = False
                remote_settings["_sync_updated"] = 500
                settings_blob = Fernet(history_key).encrypt(json.dumps({
                    "updated": 500, "settings": remote_settings
                }, separators=(",", ":")).encode()).decode("ascii")
                record = {"id": "c" * 32, "at": "now", "from": "bob",
                          "text": "arrived on device two", "reactions": []}
                message_blob = Fernet(history_key).encrypt(json.dumps({
                    "peer": "bob", "record": record
                }, separators=(",", ":")).encode()).decode("ascii")

                first, first_worker = self.authenticated_connection(server, "alice", public, signing)
                server.send(first, {"type": "sync_put_settings", "blob": settings_blob})
                self.assertEqual(server.receive(first), {"type": "sync_saved", "kind": "settings"})
                server.send(first, {"type": "sync_put_message", "id": record["id"], "blob": message_blob})
                self.assertEqual(server.receive(first), {"type": "sync_saved", "kind": "message"})
                first.close(); first_worker.join(timeout=5)
                self.assertFalse(first_worker.is_alive())

                second, second_worker = self.authenticated_connection(server, "alice", public, signing)
                server.send(second, {"type": "sync_fetch"})
                fetched = server.receive(second)
                self.assertEqual(fetched["type"], "sync_state")
                self.assertTrue(fetched["done"])

                wire.SETTINGS_FILE = root / "device-two" / "settings.json"
                app = wire.Wire.__new__(wire.Wire)
                app.history_key = history_key
                app.history_lock = threading.Lock()
                app.settings = wire.load_settings()
                app.server = None
                app.history_path = lambda peer: root / "device-two" / f"{peer}.wire"
                app.apply_sync_state(fetched)
                self.assertFalse(app.settings["notifications"])
                self.assertEqual(app.read_history("bob")[0]["text"], "arrived on device two")

                second.close(); second_worker.join(timeout=5)
                self.assertFalse(second_worker.is_alive())
                stored = server.SYNC_FILE.read_text(encoding="utf-8")
                self.assertNotIn("arrived on device two", stored)
            finally:
                server.ONLINE.clear()
                (server.STATE, server.USERS_FILE, server.GROUPS_FILE,
                 server.QUEUES_FILE, server.SYNC_FILE, server.BACKUPS_FILE) = original_paths
                wire.SETTINGS_FILE = original_settings


if __name__ == "__main__":
    unittest.main()
