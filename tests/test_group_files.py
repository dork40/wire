import base64
import os
import queue
import tempfile
import threading
import time
import unittest
from pathlib import Path

import wire
from cryptography.hazmat.primitives.asymmetric import ed25519


class FakeSocket:
    def __init__(self) -> None:
        self.inbox: "queue.Queue[dict | None]" = queue.Queue()


class TwoClientsInAGroup(unittest.TestCase):
    """Two real Wire clients joined by a fake directory that does what the
    real one does for these packets: forwards direct_offer and relay."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        root = Path(self._temp.name)
        names = ("USERS", "HISTORY_DIR", "CONTACTS_DIR", "SETTINGS_FILE", "DOWNLOADS_DIR")
        self._saved = {name: getattr(wire, name) for name in names}
        self._saved_funcs = (wire.recv_frame, wire.say, wire.toast)
        wire.USERS, wire.HISTORY_DIR, wire.CONTACTS_DIR = root / "users.json", root / "history", root / "contacts"
        wire.SETTINGS_FILE, wire.DOWNLOADS_DIR = root / "settings.json", root / "Downloads"
        wire.say = lambda _line: None
        wire.toast = lambda _text: None
        wire.recv_frame = self.fake_recv
        self.root = root

        directory = ed25519.Ed25519PrivateKey.generate()
        self.apps: dict[str, wire.Wire] = {}
        members = []
        for name in ("alice", "bob"):
            wire.Wire().signup(name, password="long enough password")
            app = wire.Wire()
            app.connect_server = lambda *args, **kwargs: None
            app.login(name, password="long enough password")
            app.directory_public = directory.public_key().public_bytes_raw()
            app.server = FakeSocket()
            app.server_send = lambda packet, sender=name: self.route(sender, packet)
            self.apps[name] = app
            signature = directory.sign(wire.directory_identity_bytes(name, app.public, app.sign_public))
            members.append({"name": name, "public": wire.b64(app.public), "sign_public": wire.b64(app.sign_public),
                            "identity_signature": wire.b64(signature), "online": True, "role": "member"})
        for app in self.apps.values():
            app.groups = {"crew": {"name": "crew", "owner": "alice", "pins": [], "members": [dict(m) for m in members]}}
            app.start_worker(app.server_loop, app.server)

    def tearDown(self) -> None:
        for app in self.apps.values():
            app.closing.set()
            app.server.inbox.put(None)
        time.sleep(0.2)
        wire.recv_frame, wire.say, wire.toast = self._saved_funcs
        for name, value in self._saved.items():
            setattr(wire, name, value)
        self._temp.cleanup()

    @staticmethod
    def fake_recv(sock):
        item = sock.inbox.get(timeout=20)
        if item is None:
            raise ConnectionError("test finished")
        return item

    def route(self, sender: str, packet: dict) -> None:
        target = self.apps.get(str(packet.get("to", "")).lower())
        if not target:
            return
        if packet["type"] == "direct_offer":
            target.server.inbox.put({"type": "direct_offer", "from": sender, "host": "127.0.0.1",
                                     "port": packet["port"], "offer": packet["offer"]})
        elif packet["type"] == "relay":
            target.server.inbox.put({"type": "relay", "from": sender, "packet": packet["packet"]})

    def wait_for(self, condition, timeout: float = 20.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = condition()
            if value:
                return value
            time.sleep(0.05)
        self.fail("timed out waiting")

    def test_group_file_arrives_intact_without_opening_a_chat(self):
        alice, bob = self.apps["alice"], self.apps["bob"]
        source = self.root / "plans.bin"
        source.write_bytes(os.urandom(300 * 1024))
        alice.group_room = "crew"
        self.assertTrue(wire.handle_input(alice, f'/send "{source}"'))

        code = self.wait_for(lambda: next(iter(bob.pending_files), None))
        self.assertEqual(bob.pending_files[code]["offer"]["group"], "crew")
        wire.run_command(bob, "file", f"accept {code[:6]}")

        received = wire.DOWNLOADS_DIR / "Files" / "plans.bin"
        self.wait_for(lambda: received.exists())
        self.assertEqual(received.read_bytes(), source.read_bytes())
        self.assertEqual(alice.peers, {})
        self.assertEqual(bob.peers, {})

    def test_transfer_link_cannot_carry_chat_messages(self):
        alice, bob = self.apps["alice"], self.apps["bob"]
        source = self.root / "x.txt"
        source.write_text("hi")
        alice.group_room = "crew"
        wire.handle_input(alice, f'/send "{source}"')
        code = self.wait_for(lambda: next(iter(bob.pending_files), None))
        wire.run_command(bob, "file", f"accept {code[:6]}")
        self.wait_for(lambda: (wire.DOWNLOADS_DIR / "Files" / "x.txt").exists())
        # Alice now has a transfer link to Bob; a chat message over it is dropped.
        alice.send_message(alice.transfer_peers["bob"], "sneaky direct message")
        time.sleep(0.5)
        self.assertEqual(bob.read_history("alice"), [])

    def test_offers_from_strangers_and_blocked_people_are_ignored(self):
        bob = self.apps["bob"]
        offer = {"id": "c" * 32, "token": "d" * 64, "name": "free.exe", "size": 10, "sha256": "e" * 64}
        bob.server.inbox.put({"type": "direct_offer", "from": "eve", "host": "1.2.3.4", "port": 1, "offer": offer})
        bob.server.inbox.put({"type": "direct_offer", "from": "eve", "host": "1.2.3.4", "port": 1,
                              "offer": dict(offer, id="f" * 32, group="crew")})  # eve isn't in crew
        contacts = bob.contacts()
        contacts["blocked"] = ["alice"]
        bob.save_contacts(contacts)
        bob.server.inbox.put({"type": "direct_offer", "from": "alice", "host": "1.2.3.4", "port": 1,
                              "offer": dict(offer, id="a" * 32, group="crew")})
        time.sleep(0.5)
        self.assertEqual(bob.pending_files, {})


if __name__ == "__main__":
    unittest.main()
