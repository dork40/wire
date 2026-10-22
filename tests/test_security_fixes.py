import base64
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

import wire
from cryptography.hazmat.primitives.asymmetric import ed25519

from test_transport import load_server_module


class ServerHarness:
    """A real wire-server.handle() over socketpairs, with state in a temp dir."""

    def __init__(self) -> None:
        self.server = load_server_module()
        self._temp = tempfile.TemporaryDirectory()
        state = Path(self._temp.name)
        self.server.STATE = state
        self.server.USERS_FILE = state / "users.json"
        self.server.GROUPS_FILE = state / "groups.json"
        self.server.QUEUES_FILE = state / "offline-queue.json"
        self.server.BACKUPS_FILE = state / "identity-backups.json"
        self.server.SYNC_FILE = state / "encrypted-sync.json"
        self.workers: list[threading.Thread] = []
        self.clients: list[socket.socket] = []

    def login(self, name: str) -> socket.socket:
        signing = ed25519.Ed25519PrivateKey.generate()
        public = base64.b64encode(name.encode().ljust(32, b"x")[:32]).decode("ascii")
        sign_public = base64.b64encode(signing.public_key().public_bytes_raw()).decode("ascii")
        client, service = socket.socketpair()
        worker = threading.Thread(target=self.server.handle, args=(service, ("127.0.0.1", 1)))
        worker.start()
        self.workers.append(worker)
        self.clients.append(client)
        self.server.send(client, {"type": "hello", "name": name, "public": public, "sign_public": sign_public})
        nonce = base64.b64decode(self.server.receive(client)["nonce"])
        signature = signing.sign(self.server.login_proof_bytes(name, nonce))
        self.server.send(client, {"type": "prove", "signature": base64.b64encode(signature).decode("ascii")})
        assert self.server.receive(client)["type"] == "ready"
        client.settimeout(5)
        return client

    def close(self) -> None:
        for client in self.clients:
            client.close()
        for worker in self.workers:
            worker.join(timeout=5)
        self._temp.cleanup()


class ForcedRoomServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = ServerHarness()
        self.server = self.harness.server

    def tearDown(self) -> None:
        self.harness.close()

    def test_accept_without_a_pending_request_is_rejected(self):
        victim = self.harness.login("victim")
        mallory = self.harness.login("mallory")
        self.server.send(mallory, {"type": "accept", "from": "victim"})
        reply = self.server.receive(mallory)
        self.assertEqual(reply["type"], "error")
        self.assertIn("no pending room request", reply["message"])
        victim.settimeout(0.3)
        with self.assertRaises(socket.timeout):
            self.server.receive(victim)

    def test_a_real_request_can_still_be_accepted_exactly_once(self):
        alice = self.harness.login("alice")
        bob = self.harness.login("bob")
        self.server.send(bob, {"type": "open", "to": "alice"})
        self.assertEqual(self.server.receive(alice)["type"], "request")
        self.assertEqual(self.server.receive(bob)["type"], "waiting")
        self.server.send(alice, {"type": "accept", "from": "bob"})
        self.assertEqual(self.server.receive(bob)["type"], "accepted")
        self.assertEqual(self.server.receive(alice)["type"], "accepted")
        # The request is consumed; replaying the accept must not re-deliver.
        self.server.send(alice, {"type": "accept", "from": "bob"})
        self.assertEqual(self.server.receive(alice)["type"], "error")

    def test_group_add_no_longer_bypasses_invite_consent(self):
        owner = self.harness.login("owner")
        self.harness.login("privateuser")
        users = self.server.load_users()
        users["privateuser"]["allow_group_invites"] = False
        self.server.save_users(users)
        self.server.send(owner, {"type": "group_create", "name": "spam", "members": []})
        self.assertEqual(self.server.receive(owner)["type"], "group_list")
        self.server.send(owner, {"type": "group_add", "group": "spam", "member": "privateuser"})
        self.assertEqual(self.server.receive(owner)["message"], "unknown request")
        self.assertEqual(self.server.load_groups()["spam"]["members"], ["owner"])

    def test_malformed_field_types_drop_only_that_connection_quietly(self):
        crashes = []
        old_hook = threading.excepthook
        threading.excepthook = crashes.append
        try:
            client = self.harness.login("sloppy")
            self.server.send(client, {"type": "open", "to": 5})
            self.harness.workers[-1].join(timeout=5)
        finally:
            threading.excepthook = old_hook
        self.assertFalse(self.harness.workers[-1].is_alive())
        self.assertEqual(crashes, [])


class AbuseLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = ServerHarness()
        self.server = self.harness.server

    def tearDown(self) -> None:
        self.harness.close()

    def test_friends_only_blocks_strangers_but_not_friends(self):
        alice = self.harness.login("alice")
        friend = self.harness.login("friend")
        stranger = self.harness.login("stranger")
        users = self.server.load_users()
        users["alice"]["friends"] = ["friend"]
        self.server.save_users(users)
        self.server.send(alice, {"type": "preferences", "friends_only_rooms": True, "allow_group_invites": True})
        self.server.send(alice, {"type": "ping", "id": "sync"})
        self.assertEqual(self.server.receive(alice)["type"], "pong")  # preferences applied
        self.server.send(stranger, {"type": "open", "to": "alice"})
        self.assertIn("only accepts chats from friends", self.server.receive(stranger)["message"])
        self.server.send(friend, {"type": "open", "to": "alice"})
        self.assertEqual(self.server.receive(alice)["type"], "request")
        self.assertEqual(self.server.receive(friend)["type"], "waiting")

    def test_password_guesses_are_capped_per_account_across_addresses(self):
        allowed = [self.server.allow_recovery(f"10.0.0.{n}", "victim") for n in range(30)]
        self.assertEqual(sum(allowed), self.server.MAX_ACCOUNT_RECOVERY_ATTEMPTS)
        self.assertTrue(self.server.allow_recovery("10.0.0.99", "someoneelse"))

    def test_new_accounts_are_capped_per_address_but_existing_logins_are_not(self):
        self.server.MAX_NEW_ACCOUNTS_PER_IP = 2
        self.harness.login("first")
        self.harness.login("second")
        with self.assertRaises(AssertionError):
            self.harness.login("third")
        self.assertNotIn("third", self.server.load_users())

    def test_one_sender_cannot_fill_the_shared_offline_queue(self):
        self.server.save_users({name: {"name": name} for name in ("spammer", "a", "b", "c", "other")})
        self.server.MAX_OFFLINE_QUEUE_BYTES_PER_SENDER = 3000
        packet = {"type": "relay", "from": "spammer", "packet": {"data": "x" * 900}}
        results = [self.server.deliver_or_queue(target, packet) for target in ("a", "b", "c", "a", "b")]
        self.assertEqual(results, [True, True, True, False, False])
        self.assertTrue(self.server.deliver_or_queue("a", {"type": "relay", "from": "other", "packet": {"data": "y" * 900}}))

    def test_status_is_cleaned_and_only_shown_to_friends_list(self):
        alice = self.harness.login("alice")
        self.harness.login("bob")
        users = self.server.load_users()
        users["alice"]["friends"], users["bob"]["friends"] = ["bob"], ["alice"]
        self.server.save_users(users)
        self.server.send(alice, {"type": "set_status", "status": "back at 6\x1b[2J\n" + "x" * 200})
        saved = self.server.receive(alice)["status"]
        self.assertTrue(saved.startswith("back at 6"))
        self.assertNotIn("\x1b", saved)
        self.assertLessEqual(len(saved), self.server.MAX_STATUS_CHARS)
        self.server.send(alice, {"type": "friends_list"})
        reply = self.server.receive(alice)
        self.assertEqual(reply["status"], saved)
        self.assertEqual(reply["users"][0]["name"], "bob")

    def test_client_can_delete_its_own_synced_message_only(self):
        alice = self.harness.login("alice")
        message_id = "a" * 32
        self.server.save_sync({"alice": {"messages": {message_id: "blob"}}, "bob": {"messages": {message_id: "blob"}}})
        self.server.send(alice, {"type": "sync_delete_message", "id": message_id})
        self.server.send(alice, {"type": "ping", "id": "done"})
        self.assertEqual(self.server.receive(alice)["type"], "pong")
        synced = self.server.load_sync()
        self.assertEqual(synced["alice"]["messages"], {})
        self.assertEqual(synced["bob"]["messages"], {message_id: "blob"})

    def test_rate_limit_tables_are_pruned(self):
        self.server.MAX_TRACKED_KEYS = 10
        # time.monotonic() counts from boot on Linux, so "0" can be recent on
        # a fresh CI machine - make the stale stamps unambiguously old.
        long_ago = time.monotonic() - self.server.RECOVERY_WINDOW_SECONDS - 60
        for n in range(50):
            self.server.RECOVERY_ATTEMPTS[f"stale-{n}"] = [long_ago]
        self.server.allow_recovery("fresh")
        self.assertLessEqual(len(self.server.RECOVERY_ATTEMPTS), 2)


class ForcedRoomClientTests(unittest.TestCase):
    def run_directory_packets(self, app: wire.Wire, packets: list[dict]) -> list[str]:
        attached: list[str] = []
        app.attach_relay_peer = lambda name, *_rest: attached.append(name)
        stream = iter(packets)

        def receive_once(_socket):
            packet = next(stream, None)
            if packet is None:
                raise ConnectionError("test stream complete")
            return packet

        old_receive, old_say = wire.recv_frame, wire.say
        wire.recv_frame, wire.say = receive_once, lambda _line: None
        try:
            app.server_loop(app.server)
        finally:
            wire.recv_frame, wire.say = old_receive, old_say
        return attached

    @staticmethod
    def accepted(name: str) -> dict:
        return {"type": "accepted", "name": name, "public": "p", "sign_public": "s", "identity_signature": "i"}

    def test_unsolicited_accepted_is_ignored(self):
        app = wire.Wire()
        app.server = object()
        self.assertEqual(self.run_directory_packets(app, [self.accepted("mallory")]), [])
        self.assertIsNone(app.room)

    def test_their_own_request_does_not_count_as_our_acceptance(self):
        # Mallory sends a room request, then "accepts" it on our behalf.
        app = wire.Wire()
        app.server = object()
        app.requests["mallory"] = '{"public": "p", "sign_public": "s"}'
        self.assertEqual(self.run_directory_packets(app, [self.accepted("mallory")]), [])

    def test_rooms_we_opened_or_accepted_still_attach(self):
        app = wire.Wire()
        app.server = object()
        sent = []
        app.server_send = sent.append
        app.is_blocked = lambda _name: False
        wire.run_command(app, "open", "Bob")
        app.requests["carol"] = '{"public": "p", "sign_public": "s"}'
        wire.run_command(app, "accept", "carol")
        attached = self.run_directory_packets(app, [self.accepted("Bob"), self.accepted("carol"), self.accepted("Bob")])
        self.assertEqual(attached, ["Bob", "carol"])
        self.assertEqual([packet["type"] for packet in sent], ["open", "accept"])


class UntrustedNameTests(unittest.TestCase):
    def test_folder_parts_are_dropped_on_every_os(self):
        self.assertEqual(wire.safe_filename("..\\..\\Windows\\evil.exe"), "evil.exe")
        self.assertEqual(wire.safe_filename("../../.bashrc"), ".bashrc")

    def test_reversed_text_trick_is_removed(self):
        self.assertEqual(wire.safe_filename("invoice_‮fdp.exe"), "invoice_fdp.exe")
        self.assertNotIn("‮", wire.safe_terminal_text("invoice_‮fdp.exe"))

    def test_terminal_escape_sequences_cannot_survive(self):
        # OSC 52 asks the terminal to overwrite the clipboard.
        name = wire.safe_filename("\x1b]52;c;ZXZpbA==\x07cat.png")
        self.assertTrue(all(ord(char) >= 32 for char in name))
        self.assertTrue(name.endswith("cat.png"))

    def test_windows_specific_tricks(self):
        self.assertEqual(wire.safe_filename("notes.txt:hidden"), "notes.txt_hidden")
        self.assertEqual(wire.safe_filename("CON.txt"), "_CON.txt")
        self.assertEqual(wire.safe_filename("report.pdf. . "), "report.pdf")

    def test_empty_and_dot_names_fall_back(self):
        for value in ("", ".", "..", "/", "‮"):
            self.assertEqual(wire.safe_filename(value, "image"), "image")

    def test_emoji_joiners_are_kept_in_chat_text(self):
        family = "\U0001F468‍\U0001F469‍\U0001F467"
        self.assertEqual(wire.safe_terminal_text(family), family)


if __name__ == "__main__":
    unittest.main()
