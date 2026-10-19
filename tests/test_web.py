import base64
import hashlib
import importlib.util
import json
import socket
import struct
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
import zipfile

from cryptography.fernet import Fernet


def load_web():
    path = Path(__file__).resolve().parents[1] / "wire-web.py"
    spec = importlib.util.spec_from_file_location("wire_web_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WebConsoleTests(unittest.TestCase):
    def test_security_status_verifies_backup_and_turn_listener(self):
        web = load_web()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); web.STATE = root; web.BACKUPS = root
            for name in ("server-signing-key", "server-certificate.pem", "server-tls-key.pem"):
                (root / name).write_bytes(b"protected")
            state_data = b'{"alice":{"name":"Alice"}}'
            manifest = {"format": 1, "files": {"users.json": hashlib.sha256(state_data).hexdigest()}}
            backup = root / "wire-state-20261018T000000Z.zip"
            with zipfile.ZipFile(backup, "w") as archive:
                archive.writestr("manifest.json", json.dumps(manifest))
                archive.writestr("state/users.json", state_data)

            listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            listener.bind(("127.0.0.1", 0)); port = listener.getsockname()[1]
            def answer():
                request, address = listener.recvfrom(2048)
                listener.sendto(struct.pack("!HHI", 0x0101, 0, 0x2112A442) + request[8:20], address)
            worker = threading.Thread(target=answer); worker.start()
            try:
                self.assertTrue(web.turn_reachable("127.0.0.1", port))
                status = web.server_security_status()
                self.assertTrue(status["identity"])
                self.assertTrue(status["backup"]["ok"])
                self.assertEqual(status["backup"]["count"], 1)
            finally:
                worker.join(timeout=2); listener.close()

            with zipfile.ZipFile(backup, "w") as archive:
                archive.writestr("manifest.json", json.dumps(manifest))
                archive.writestr("state/users.json", b"tampered")
            self.assertFalse(web.verify_latest_backup()["ok"])

    def test_requires_wire_account_login_before_showing_private_data(self):
        web = load_web()
        with tempfile.TemporaryDirectory() as folder:
            web.STATE = Path(folder); web.BACKUPS = Path(folder)
            password, salt = "correct horse battery staple", b"0123456789abcdef"
            kdf = {"n": 2**14, "r": 8, "p": 1}
            secret = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **kdf)
            identity_public = bytes(range(32))
            account = {"name": "Alice", "private": "encrypted", "friends": ["bob"]}
            backup = {"salt": base64.b64encode(salt).decode(), "kdf": kdf,
                      "ciphertext": Fernet(base64.urlsafe_b64encode(secret)).encrypt(json.dumps(account).encode()).decode()}
            (web.STATE / "identity-backups.json").write_text(json.dumps({"alice": backup}), encoding="utf-8")
            (web.STATE / "users.json").write_text(json.dumps({"alice": {"name": "Alice", "friends": ["bob"], "public": base64.b64encode(identity_public).decode()}, "bob": {"name": "Bob"}}), encoding="utf-8")
            server = web.WireWebServer(("127.0.0.1", 0), web.Handler)
            self.assertTrue(server.daemon_threads)
            worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                public = urllib.request.urlopen(base + "/").read().decode()
                self.assertIn("Welcome back", public); self.assertNotIn("Bob", public)
                protected = urllib.request.urlopen(base + "/server")
                self.assertIn("Welcome back", protected.read().decode())
                self.assertIn("default-src 'none'", protected.headers["Content-Security-Policy"])
                self.assertEqual(protected.headers["Permissions-Policy"], "camera=(), microphone=(), geolocation=()")
                request = urllib.request.Request(base + "/login", data=urllib.parse.urlencode({"username":"alice", "password":password}).encode(), method="POST")
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl): return None
                opener = urllib.request.build_opener(NoRedirect())
                response_obj = None
                try: opener.open(request)
                except urllib.error.HTTPError as response:
                    self.assertEqual(response.code, 303); response_obj = response
                cookie = response_obj.headers.get("Set-Cookie")
                self.assertIn("HttpOnly", cookie); self.assertIn("SameSite=Strict", cookie)
                dashboard = urllib.request.urlopen(urllib.request.Request(base + "/", headers={"Cookie": cookie.split(";", 1)[0]})).read().decode()
                self.assertIn("Hello, Alice", dashboard); self.assertIn("Bob", dashboard)
                people = urllib.request.urlopen(urllib.request.Request(base + "/people", headers={"Cookie": cookie.split(";", 1)[0]})).read().decode()
                groups = urllib.request.urlopen(urllib.request.Request(base + "/groups", headers={"Cookie": cookie.split(";", 1)[0]})).read().decode()
                account_page = urllib.request.urlopen(urllib.request.Request(base + "/account", headers={"Cookie": cookie.split(";", 1)[0]})).read().decode()
                status = urllib.request.urlopen(urllib.request.Request(base + "/server", headers={"Cookie": cookie.split(";", 1)[0]})).read().decode()
                self.assertIn("Encrypted contact", people)
                self.assertIn("No group memberships yet", groups)
                self.assertIn("Safety fingerprint", account_page)
                self.assertNotIn("correct horse battery staple", account_page)
                expected_fingerprint = " ".join(hashlib.sha256(identity_public).hexdigest().upper()[i:i + 4] for i in range(0, 64, 4))
                self.assertIn(expected_fingerprint, account_page)
                self.assertIn("Security boundaries", status)
                with self.assertRaises(urllib.error.HTTPError) as rejected_logout:
                    urllib.request.urlopen(urllib.request.Request(base + "/logout", headers={"Cookie": cookie.split(";", 1)[0]}))
                self.assertEqual(rejected_logout.exception.code, 405)
                logout = urllib.request.Request(base + "/logout", data=b"", method="POST",
                                                headers={"Cookie": cookie.split(";", 1)[0]})
                try: opener.open(logout)
                except urllib.error.HTTPError as response: self.assertEqual(response.code, 303)
            finally:
                server.shutdown(); server.server_close(); worker.join(timeout=2)

    def test_malformed_account_metadata_does_not_crash_pages(self):
        web = load_web()
        with tempfile.TemporaryDirectory() as folder:
            web.STATE = Path(folder); web.BACKUPS = Path(folder)
            (web.STATE / "users.json").write_text(json.dumps({"alice": {"name": "Alice", "friends": "not-a-list", "public": "broken"},
                                                               "bob": "not-an-account"}), encoding="utf-8")
            (web.STATE / "groups.json").write_text(json.dumps({"bad": {"name": "Bad", "members": "alice"}}), encoding="utf-8")
            for page in (web.overview_page, web.people_page, web.groups_page, web.account_page):
                rendered = page("alice").decode("utf-8")
                self.assertIn("Wire", rendered)
            self.assertIn("Unavailable", web.account_page("alice").decode("utf-8"))

    def test_legacy_account_without_kdf_uses_client_compatible_defaults(self):
        web = load_web()
        with tempfile.TemporaryDirectory() as folder:
            web.STATE = Path(folder)
            password, salt = "legacy password", b"legacy-salt-1234"
            secret = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
            account = {"name": "dorki", "private": "encrypted"}
            backup = {
                "salt": base64.b64encode(salt).decode(),
                "ciphertext": Fernet(base64.urlsafe_b64encode(secret)).encrypt(
                    json.dumps(account).encode()
                ).decode(),
            }
            (web.STATE / "identity-backups.json").write_text(
                json.dumps({"dorki": backup}), encoding="utf-8"
            )

            self.assertEqual(web.verify_account("dorki", password), account)
            self.assertIsNone(web.verify_account("dorki", "wrong password"))

    def test_web_login_rejects_excessive_kdf_before_derivation(self):
        web = load_web()
        with tempfile.TemporaryDirectory() as folder:
            web.STATE = Path(folder)
            backup = {"salt": base64.b64encode(b"0123456789abcdef").decode(),
                      "kdf": {"n": 2**20, "r": 32, "p": 16}, "ciphertext": "unused"}
            (web.STATE / "identity-backups.json").write_text(json.dumps({"alice": backup}), encoding="utf-8")
            original = web.hashlib.scrypt
            def unexpected_derivation(*args, **kwargs):
                raise AssertionError("unsafe KDF reached scrypt")
            web.hashlib.scrypt = unexpected_derivation
            try: self.assertIsNone(web.verify_account("alice", "password"))
            finally: web.hashlib.scrypt = original


if __name__ == "__main__": unittest.main()
