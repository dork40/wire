import hashlib
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


def load_server_module():
    path = Path(__file__).parents[1] / "wire-server.py"
    spec = importlib.util.spec_from_file_location("wire_server_backup_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ServerBackupTests(unittest.TestCase):
    def test_backup_verifies_and_restores_server_identity_and_data(self):
        server = load_server_module()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            server.STATE = root / "state"
            server.BACKUP_DIR = root / "backups"
            server.BACKUP_RETAIN = 4
            server.STATE.mkdir()
            original = {"users.json": b'{"alice":{"public":"opaque"}}',
                        "server-signing-key": b"persistent-directory-identity"}
            for name, data in original.items():
                (server.STATE / name).write_bytes(data)
            backup = server.create_state_backup()
            self.assertIsNotNone(backup)
            self.assertEqual(server.verified_backup_files(backup), original)
            (server.STATE / "users.json").write_bytes(b"damaged")
            server.restore_state_backup(backup)
            self.assertEqual((server.STATE / "users.json").read_bytes(), original["users.json"])
            self.assertEqual((server.STATE / "server-signing-key").read_bytes(), original["server-signing-key"])

    def test_modified_backup_is_rejected(self):
        server = load_server_module()
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "bad.zip"
            manifest = {"format": 1, "files": {"users.json": hashlib.sha256(b"original").hexdigest()}}
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("manifest.json", json.dumps(manifest))
                archive.writestr("state/users.json", b"changed")
            with self.assertRaisesRegex(ValueError, "verification failed"):
                server.verified_backup_files(source)
