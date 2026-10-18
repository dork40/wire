import base64
import hashlib
import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.fernet import Fernet


def load_web():
    path = Path(__file__).resolve().parents[1] / "wire-web.py"
    spec = importlib.util.spec_from_file_location("wire_web_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WebConsoleTests(unittest.TestCase):
    def test_requires_wire_account_login_before_showing_private_data(self):
        web = load_web()
        with tempfile.TemporaryDirectory() as folder:
            web.STATE = Path(folder); web.BACKUPS = Path(folder)
            password, salt = "correct horse battery staple", b"0123456789abcdef"
            kdf = {"n": 2**14, "r": 8, "p": 1}
            secret = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **kdf)
            account = {"name": "Alice", "private": "encrypted", "friends": ["bob"]}
            backup = {"salt": base64.b64encode(salt).decode(), "kdf": kdf,
                      "ciphertext": Fernet(base64.urlsafe_b64encode(secret)).encrypt(json.dumps(account).encode()).decode()}
            (web.STATE / "identity-backups.json").write_text(json.dumps({"alice": backup}), encoding="utf-8")
            (web.STATE / "users.json").write_text(json.dumps({"alice": {"name": "Alice", "friends": ["bob"]}, "bob": {"name": "Bob"}}), encoding="utf-8")
            server = web.ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
            worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                public = urllib.request.urlopen(base + "/").read().decode()
                self.assertIn("Welcome back", public); self.assertNotIn("Bob", public)
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
            finally:
                server.shutdown(); server.server_close(); worker.join(timeout=2)


if __name__ == "__main__": unittest.main()
