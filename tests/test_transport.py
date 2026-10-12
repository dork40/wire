import importlib.util
import base64
import os
import socket
import threading
import tempfile
import unittest
from pathlib import Path

import wire
from cryptography.hazmat.primitives.asymmetric import ed25519


def load_server_module():
    path = Path(__file__).parents[1] / "wire-server.py"
    spec = importlib.util.spec_from_file_location("wire_server_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TransportTests(unittest.TestCase):
    def test_identity_recovery_requires_password_proof(self):
        server = load_server_module()
        original_state, original_backups = server.STATE, server.BACKUPS_FILE
        secret = b"s" * 32
        backup = {"salt": "c2FsdA==", "ciphertext": "encrypted-account", "recovery_proof": server.recovery_proof(secret)}
        with tempfile.TemporaryDirectory() as temporary:
            server.STATE = Path(temporary)
            server.BACKUPS_FILE = server.STATE / "identity-backups.json"
            server.save_backups({"alice": backup})
            for proof, expected in ((backup["recovery_proof"], "identity_backup"), ("0" * 64, "error")):
                client, service = socket.socketpair()
                worker = threading.Thread(target=server.handle, args=(service, ("127.0.0.1", 1)))
                worker.start()
                server.send(client, {"type": "identity_fetch", "name": "alice"})
                challenge = server.receive(client)
                self.assertEqual(challenge["type"], "identity_recovery_challenge")
                self.assertNotIn("ciphertext", challenge)
                server.send(client, {"type": "identity_fetch_prove", "proof": proof})
                reply = server.receive(client)
                self.assertEqual(reply["type"], expected)
                if expected == "error": self.assertNotIn("backup", reply)
                client.close(); worker.join(timeout=5)
        server.STATE, server.BACKUPS_FILE = original_state, original_backups

    def test_relay_limits_reject_queue_floods_and_rate_bursts(self):
        server = load_server_module()
        original = (server.STATE, server.USERS_FILE, server.QUEUES_FILE,
                    server.MAX_OFFLINE_QUEUE_PACKETS, server.MAX_OFFLINE_QUEUE_BYTES,
                    server.RELAY_RATE_BYTES_PER_SECOND, server.RELAY_RATE_BURST_BYTES)
        with tempfile.TemporaryDirectory() as temporary:
            server.STATE = Path(temporary)
            server.USERS_FILE, server.QUEUES_FILE = server.STATE / "users.json", server.STATE / "offline-queue.json"
            server.save_users({"target": {"name": "target"}})
            server.ONLINE.clear()
            server.MAX_OFFLINE_QUEUE_PACKETS, server.MAX_OFFLINE_QUEUE_BYTES = 2, 100
            packet = {"type": "relay", "payload": "x" * 20}
            self.assertTrue(server.deliver_or_queue("target", packet))
            self.assertTrue(server.deliver_or_queue("target", packet))
            self.assertFalse(server.deliver_or_queue("target", packet))
            server.RELAY_RATE_BYTES_PER_SECOND, server.RELAY_RATE_BURST_BYTES = 1, 10
            server.RELAY_BUDGETS.clear()
            self.assertTrue(server.allow_relay("sender", 8))
            self.assertFalse(server.allow_relay("sender", 8))
        (server.STATE, server.USERS_FILE, server.QUEUES_FILE,
         server.MAX_OFFLINE_QUEUE_PACKETS, server.MAX_OFFLINE_QUEUE_BYTES,
         server.RELAY_RATE_BYTES_PER_SECOND, server.RELAY_RATE_BURST_BYTES) = original

    def test_group_creation_respects_invite_permission(self):
        server = load_server_module()
        original = (server.STATE, server.USERS_FILE, server.GROUPS_FILE, server.QUEUES_FILE)
        signing = ed25519.Ed25519PrivateKey.generate()
        public = base64.b64encode(b"p" * 32).decode("ascii")
        signing_public = base64.b64encode(signing.public_key().public_bytes_raw()).decode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            server.STATE = Path(temporary)
            server.USERS_FILE = server.STATE / "users.json"
            server.GROUPS_FILE = server.STATE / "groups.json"
            server.QUEUES_FILE = server.STATE / "offline-queue.json"
            server.save_users({
                "owner": {"name": "owner", "public": public, "sign_public": signing_public},
                "privateuser": {"name": "privateuser", "public": public, "sign_public": signing_public, "allow_group_invites": False},
            })
            client, service = socket.socketpair()
            worker = threading.Thread(target=server.handle, args=(service, ("127.0.0.1", 1)))
            worker.start()
            server.send(client, {"type": "hello", "name": "owner", "public": public, "sign_public": signing_public})
            challenge = server.receive(client)
            nonce = base64.b64decode(challenge["nonce"])
            signature = signing.sign(server.login_proof_bytes("owner", nonce))
            server.send(client, {"type": "prove", "signature": base64.b64encode(signature).decode("ascii")})
            self.assertEqual(server.receive(client)["type"], "ready")
            server.send(client, {"type": "group_create", "name": "consent", "members": ["privateuser"]})
            self.assertEqual(server.receive(client)["type"], "group_list")
            group = server.load_groups()["consent"]
            self.assertEqual(group["members"], ["owner"])
            self.assertEqual(group["invites"], [])
            client.close(); worker.join(timeout=5)
        server.STATE, server.USERS_FILE, server.GROUPS_FILE, server.QUEUES_FILE = original

    def test_server_rejects_slow_unauthed_connections_and_caps_workers(self):
        server = load_server_module()

        class SlowSocket:
            def __init__(self): self.timeouts = []; self.closed = False
            def settimeout(self, value): self.timeouts.append(value)
            def close(self): self.closed = True

        slow = SlowSocket()
        original_receive = server.receive
        server.receive = lambda _: (_ for _ in ()).throw(socket.timeout())
        try:
            server.handle(slow, ("127.0.0.1", 1))
        finally:
            server.receive = original_receive
        self.assertEqual(slow.timeouts, [15])
        self.assertTrue(slow.closed)

        acquired = [server.CONNECTION_SLOTS.acquire(blocking=False) for _ in range(server.MAX_CONNECTIONS)]
        try:
            self.assertTrue(all(acquired))
            self.assertFalse(server.CONNECTION_SLOTS.acquire(blocking=False))
        finally:
            for _ in acquired: server.CONNECTION_SLOTS.release()

    def test_server_packets_do_not_interleave(self):
        server = load_server_module()
        sender, receiver = socket.socketpair()
        received = []
        total_threads, per_thread = 4, 30

        def read():
            for _ in range(total_threads * per_thread):
                received.append(server.receive(receiver))

        def write(worker):
            for sequence in range(per_thread):
                server.send(sender, {"type": "test", "worker": worker, "sequence": sequence, "body": "x" * 4096})

        reader = threading.Thread(target=read)
        reader.start()
        writers = [threading.Thread(target=write, args=(worker,)) for worker in range(total_threads)]
        for writer in writers: writer.start()
        for writer in writers: writer.join()
        sender.shutdown(socket.SHUT_WR)
        reader.join(timeout=10)
        sender.close(); receiver.close()
        self.assertEqual(len(received), total_threads * per_thread)
        self.assertEqual({(item["worker"], item["sequence"]) for item in received},
                         {(worker, sequence) for worker in range(total_threads) for sequence in range(per_thread)})

    def test_direct_peer_packets_do_not_interleave(self):
        sender, receiver = socket.socketpair()
        peer = wire.Peer("test", sender, os.urandom(32), os.urandom(32))
        received = []
        total_threads, per_thread = 4, 30

        def read():
            for _ in range(total_threads * per_thread):
                received.append(wire.recv_frame(receiver))

        def write(worker):
            for sequence in range(per_thread):
                peer.send_control({"kind": "test", "worker": worker, "sequence": sequence, "body": "x" * 4096})

        reader = threading.Thread(target=read)
        reader.start()
        writers = [threading.Thread(target=write, args=(worker,)) for worker in range(total_threads)]
        for writer in writers: writer.start()
        for writer in writers: writer.join()
        sender.shutdown(socket.SHUT_WR)
        reader.join(timeout=10)
        sender.close(); receiver.close()
        self.assertEqual(len(received), total_threads * per_thread)
        self.assertTrue(all(item["type"] == "control" for item in received))

    def test_share_answer_targets_exact_share(self):
        class Media:
            def __init__(self): self.received = []
            def remote(self, answer): self.received.append(("remote", answer)); return answer
            def call(self, answer): self.received.append(("call", answer))

        class Socket: pass

        app, socket_stub = wire.Wire(), Socket()
        first, target = Media(), Media()
        app.webrtc_shares = {"first": first, "target": target}
        app.server = socket_stub
        packets = iter([{"type": "share_answer", "id": "target", "answer": {"sdp": "answer"}}])
        old_receive, old_say = wire.recv_frame, wire.say
        wire.recv_frame, wire.say = lambda _: next(packets), lambda _: None
        try:
            app.server_loop(socket_stub)
        finally:
            wire.recv_frame, wire.say = old_receive, old_say
        self.assertEqual(first.received, [])
        self.assertEqual(target.received, [("remote", {"sdp": "answer"}), ("call", {"sdp": "answer"})])


if __name__ == "__main__":
    unittest.main()
