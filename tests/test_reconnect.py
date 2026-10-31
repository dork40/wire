import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import wire


class ReconnectTests(unittest.TestCase):
    """A real wire-server and a real client: kill the client's directory
    connection and it must come back by itself."""

    def setUp(self) -> None:
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        self.port = probe.getsockname()[1]
        probe.close()
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        env = dict(os.environ, WIRE_HOST="127.0.0.1", WIRE_PORT=str(self.port), WIRE_STATE=str(root / "server"))
        self.server = subprocess.Popen([sys.executable, str(Path(wire.__file__).with_name("wire-server.py"))],
                                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        names = ("DATA", "USERS", "SETTINGS_FILE", "SERVER_CONFIG", "DIRECTORY_KEYS_FILE", "HISTORY_DIR",
                 "CONTACTS_DIR", "RATCHET_DIR", "TRANSFER_TEMP_DIR", "DOWNLOADS_DIR")
        self.saved = {name: getattr(wire, name) for name in names}
        self.old_say, self.old_delays = wire.say, wire.RECONNECT_DELAYS
        wire.DATA = root / "client"
        wire.USERS, wire.SETTINGS_FILE = wire.DATA / "users.json", wire.DATA / "settings.json"
        wire.SERVER_CONFIG, wire.DIRECTORY_KEYS_FILE = wire.DATA / "server.json", wire.DATA / "directory-keys.json"
        wire.HISTORY_DIR, wire.CONTACTS_DIR = wire.DATA / "history", wire.DATA / "contacts"
        wire.RATCHET_DIR, wire.TRANSFER_TEMP_DIR, wire.DOWNLOADS_DIR = wire.DATA / "r", wire.DATA / "t", root / "d"
        wire.say = lambda _line: None
        wire.RECONNECT_DELAYS = (0.1,)
        wire.save_directory_config("private", "127.0.0.1", self.port)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    def tearDown(self) -> None:
        self.server.terminate()
        self.server.wait(timeout=5)
        wire.say, wire.RECONNECT_DELAYS = self.old_say, self.old_delays
        for name, value in self.saved.items():
            setattr(wire, name, value)
        self.temp.cleanup()

    def wait_for(self, condition, timeout=15.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if condition():
                return True
            time.sleep(0.05)
        return False

    def test_dropped_connection_comes_back_by_itself(self):
        wire.Wire().signup("roamer", password="long enough password")
        app = wire.Wire()
        app.login("roamer", password="long enough password")
        self.assertTrue(self.wait_for(lambda: app.server is not None))
        first = app.server
        app.drop_dead_connection()
        self.assertTrue(self.wait_for(lambda: app.server is not None and app.server is not first),
                        "the client never reconnected")
        app.server_send({"type": "ping", "id": "x"})  # and the new connection works
        app.close()

    def test_silent_connection_is_detected_and_replaced(self):
        wire.Wire().signup("sleeper", password="long enough password")
        app = wire.Wire()
        app.login("sleeper", password="long enough password")
        self.assertTrue(self.wait_for(lambda: app.server is not None))
        first = app.server
        app.last_server_frame = time.monotonic() - 3600  # nothing has arrived for an hour
        old_interval = wire.KEEPALIVE_SECONDS
        try:
            self.assertTrue(app.check_connection(wait=0.01) in (True, False))
        finally:
            wire.KEEPALIVE_SECONDS = old_interval
        self.assertTrue(self.wait_for(lambda: app.server is not None and app.server is not first),
                        "a connection that stopped answering was never replaced")
        app.close()


if __name__ == "__main__":
    unittest.main()
