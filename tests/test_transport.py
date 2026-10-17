import importlib.util
import base64
import hashlib
import hmac
import os
import socket
import subprocess
import sys
import threading
import tempfile
import time
import unittest
import json
from pathlib import Path

import wire
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
from PIL import Image


def load_server_module():
    path = Path(__file__).parents[1] / "wire-server.py"
    spec = importlib.util.spec_from_file_location("wire_server_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TransportTests(unittest.TestCase):
    def test_terminal_control_sequences_are_removed(self):
        hostile = "hello\x1b[2J\x1b]0;fake title\x07world"
        rendered = wire.Wire().render_record({"from": "peer", "text": hostile})
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertIn("hello", rendered)
        self.assertIn("world", rendered)

    def test_replayed_encrypted_nonce_is_rejected(self):
        peer = wire.Peer("peer", None, os.urandom(32), os.urandom(32))
        packet = {"nonce": wire.b64(os.urandom(12))}
        self.assertTrue(peer.accept_nonce(packet))
        self.assertFalse(peer.accept_nonce(packet))

    def test_corrupt_encrypted_media_does_not_disconnect_or_raise(self):
        app = wire.Wire()
        peer = wire.Peer("peer", None, os.urandom(32), os.urandom(32))
        for packet_type in ("msg", "image", "voice", "audio", "file_relay", "control"):
            packet = {"type": packet_type, "nonce": wire.b64(os.urandom(12)),
                      "data": wire.b64(os.urandom(32))}
            app.handle_message(peer, packet)

    def test_typing_updates_keep_only_one_expiry_timer_per_peer(self):
        app = wire.Wire()
        key = os.urandom(32)
        peer = wire.Peer("peer", None, key, os.urandom(32))
        for _ in range(20):
            nonce = os.urandom(12)
            control = json.dumps({"kind": "typing"}, separators=(",", ":")).encode()
            packet = {"type": "control", "nonce": wire.b64(nonce),
                      "data": wire.b64(AESGCM(key).encrypt(nonce, control, b"wire-v1-control"))}
            app.handle_message(peer, packet)
        self.assertEqual(list(app.typing_timers), ["peer"])
        app.close()

    def test_shutdown_drains_network_workers_before_stdout_finalizes(self):
        app = wire.Wire()
        server_side, server_peer = socket.socketpair()
        room_side, room_peer = socket.socketpair()
        app.server = server_side
        peer = wire.Peer("peer", room_side, os.urandom(32), os.urandom(32))
        app.peers["peer"] = peer
        app.start_worker(app.server_loop, server_side)
        app.start_worker(app.receive_loop, peer)
        app.close()
        server_peer.close(); room_peer.close()
        with app.background_threads_lock:
            self.assertEqual(app.background_threads, set())

    def test_legacy_users_file_drops_password_derived_key_copy(self):
        original_data, original_users = wire.DATA, wire.USERS
        with tempfile.TemporaryDirectory() as temporary:
            wire.DATA, wire.USERS = Path(temporary), Path(temporary) / "users.json"
            salt = os.urandom(16)
            secret = wire.derive("password", salt)
            private = Fernet(base64.urlsafe_b64encode(secret)).encrypt(b"p" * 32).decode("ascii")
            wire.USERS.write_text(json.dumps({"alice": {"name": "alice", "salt": wire.b64(salt), "check": wire.b64(secret), "private": private}}), encoding="utf-8")
            loaded = wire.load_users()
            self.assertNotIn("check", loaded["alice"])
            self.assertNotIn("check", wire.USERS.read_text(encoding="utf-8"))
        wire.DATA, wire.USERS = original_data, original_users

    def test_new_password_kdf_meets_configured_work_factor(self):
        self.assertEqual(wire.CURRENT_KDF, {"name": "scrypt", "n": 2**14, "r": 8, "p": 5})

    def test_share_menu_does_not_advertise_unverified_high_fps(self):
        self.assertEqual(max(wire.STREAM_FPS), 60)

    def test_gif_frame_has_compact_terminal_rendering(self):
        image = Image.new("RGB", (8, 8), (10, 20, 30))
        text, lines = wire.Wire.gif_frame_text(image, "motion.gif")
        self.assertIn("GIF: motion.gif", text)
        self.assertGreater(lines, 1)

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

    def test_identity_recovery_v2_uses_one_time_challenge(self):
        server = load_server_module()
        original_state, original_backups = server.STATE, server.BACKUPS_FILE
        secret = b"s" * 32
        verifier = hmac.new(secret, b"wire-v2-identity-recovery", hashlib.sha256).hexdigest()
        backup = {"salt": "c2FsdA==", "kdf": wire.CURRENT_KDF, "ciphertext": "encrypted-account", "recovery_verifier": verifier}
        with tempfile.TemporaryDirectory() as temporary:
            server.STATE = Path(temporary)
            server.BACKUPS_FILE = server.STATE / "identity-backups.json"
            server.RECOVERY_ATTEMPTS.clear()
            server.save_backups({"alice": backup})
            client, service = socket.socketpair()
            worker = threading.Thread(target=server.handle, args=(service, ("127.0.0.2", 1)))
            worker.start()
            server.send(client, {"type": "identity_fetch", "name": "alice"})
            challenge = server.receive(client)
            nonce = base64.b64decode(challenge["challenge"])
            proof = hmac.new(bytes.fromhex(verifier), nonce, hashlib.sha256).hexdigest()
            server.send(client, {"type": "identity_fetch_prove", "proof": proof})
            self.assertEqual(server.receive(client)["type"], "identity_backup")
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

    def test_attachment_pacing_reserves_one_shared_budget(self):
        app = wire.Wire()
        original_rate, original_monotonic, original_sleep = (
            wire.RELAY_UPLOAD_BYTES_PER_SECOND, wire.time.monotonic, wire.time.sleep
        )
        clock, delays = [100.0], []
        wire.RELAY_UPLOAD_BYTES_PER_SECOND = 1000
        wire.time.monotonic = lambda: clock[0]

        def pretend_sleep(delay):
            delays.append(delay)
            clock[0] += delay

        wire.time.sleep = pretend_sleep
        try:
            app.pace_relay_upload(100)
            app.pace_relay_upload(100)
        finally:
            wire.RELAY_UPLOAD_BYTES_PER_SECOND, wire.time.monotonic, wire.time.sleep = (
                original_rate, original_monotonic, original_sleep
            )
        self.assertEqual(len(delays), 1)
        self.assertGreater(delays[0], 0)

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
            directory_public = base64.b64decode(challenge["server_sign_public"])
            ed25519.Ed25519PublicKey.from_public_bytes(directory_public).verify(
                base64.b64decode(challenge["server_signature"]),
                server.directory_proof_bytes("owner", public, signing_public, nonce),
            )
            signature = signing.sign(server.login_proof_bytes("owner", nonce))
            server.send(client, {"type": "prove", "signature": base64.b64encode(signature).decode("ascii")})
            ready = server.receive(client)
            self.assertEqual(ready["type"], "ready")
            self.assertEqual(ready["relay_rate"], server.RELAY_RATE_BYTES_PER_SECOND)
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

    def test_directory_main_uses_tls_and_pins_its_key(self):
        probe = socket.socket(); probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]; probe.close()
        original_data, original_keys = wire.DATA, wire.DIRECTORY_KEYS_FILE
        with tempfile.TemporaryDirectory() as temporary:
            environment = os.environ.copy()
            environment.update({"WIRE_HOST": "127.0.0.1", "WIRE_PORT": str(port), "WIRE_STATE": str(Path(temporary) / "server")})
            process = subprocess.Popen([sys.executable, str(Path(__file__).parents[1] / "wire-server.py")], env=environment,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                wire.DATA = Path(temporary) / "client"
                wire.DIRECTORY_KEYS_FILE = wire.DATA / "directory-keys.json"
                deadline = time.monotonic() + 5
                while True:
                    try:
                        connection, key = wire.open_directory_socket("127.0.0.1", port, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self.fail(f"TLS directory did not start: {process.stderr.read().decode(errors='replace')}")
                        time.sleep(0.05)
                self.assertIn(connection.version(), {"TLSv1.2", "TLSv1.3"})
                self.assertEqual(len(key), 32)
                connection.close()
                self.assertTrue(wire.DIRECTORY_KEYS_FILE.exists())
            finally:
                process.terminate(); process.wait(timeout=5)
                if process.stderr: process.stderr.close()
                wire.DATA, wire.DIRECTORY_KEYS_FILE = original_data, original_keys

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
        def receive_once(_socket):
            packet = next(packets, None)
            if packet is None:
                raise ConnectionError("test stream complete")
            return packet
        wire.recv_frame, wire.say = receive_once, lambda _: None
        try:
            app.server_loop(socket_stub)
        finally:
            wire.recv_frame, wire.say = old_receive, old_say
        self.assertEqual(first.received, [])
        self.assertEqual(target.received, [("remote", {"sdp": "answer"}), ("call", {"sdp": "answer"})])

    def test_screen_share_offer_is_received_inside_encrypted_control(self):
        app = wire.Wire()
        key, share_id = os.urandom(32), "a" * 32
        peer = wire.Peer("alice", None, key, os.urandom(32))
        offer = {"id": share_id, "sdp": "private-sdp", "resolution": [1280, 720], "fps": 60}
        control = json.dumps({"kind": "webrtc_offer", "id": share_id, "offer": offer}, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        packet = {"type": "control", "nonce": wire.b64(nonce),
                  "data": wire.b64(AESGCM(key).encrypt(nonce, control, b"wire-v1-control"))}
        original_say, original_redraw = wire.say, wire.redraw_prompt
        wire.say, wire.redraw_prompt = lambda _: None, lambda: None
        try:
            app.handle_message(peer, packet)
        finally:
            wire.say, wire.redraw_prompt = original_say, original_redraw
        self.assertEqual(app.pending_shares[share_id]["offer"]["sdp"], "private-sdp")

    def test_malformed_screen_share_offer_is_rejected(self):
        share_id = "b" * 32
        self.assertFalse(wire.valid_share_offer({"id": share_id, "sdp": "x", "resolution": [], "fps": 60}, share_id))
        self.assertFalse(wire.valid_share_offer({"id": share_id, "sdp": "x", "resolution": [1920, 1080], "fps": 1000}, share_id))

    def test_updater_no_longer_executes_remote_powershell(self):
        source = Path(wire.__file__).read_text(encoding="utf-8")
        self.assertNotIn("irm {INSTALL_SCRIPT_URL} | iex", source)
        self.assertIn("wire/archive/{commit}.zip", source)
        root = Path(__file__).parents[1]
        cmd_installer = (root / "install-wire.cmd").read_text(encoding="utf-8").lower()
        linux_installer = (root / "install-wire.sh").read_text(encoding="utf-8")
        self.assertNotIn("invoke-expression", cmd_installer)
        self.assertNotIn("executionpolicy bypass", cmd_installer)
        self.assertNotIn("pacman -Sy ", linux_installer)

    def test_current_identity_backup_format_is_accepted_by_server(self):
        server = load_server_module()
        backup = {"salt": wire.b64(os.urandom(16)), "kdf": wire.CURRENT_KDF,
                  "ciphertext": "encrypted", "recovery_verifier": "a" * 64}
        self.assertTrue(server.valid_identity_backup(backup))
        self.assertFalse(server.valid_identity_backup({**backup, "recovery_verifier": "not-hex"}))

    def test_identity_backup_rolls_out_without_breaking_v1422(self):
        app = wire.Wire()
        app.name, app.account_secret = "alice", os.urandom(32)
        account = {"name": "alice", "salt": wire.b64(os.urandom(16)), "kdf": wire.CURRENT_KDF}
        sent, original_load = [], wire.load_users
        wire.load_users = lambda: {"alice": account}
        app.server_send = sent.append
        try:
            app.backup_identity()
        finally:
            wire.load_users = original_load
        backup = sent[0]["backup"]
        self.assertRegex(backup["recovery_verifier"], r"^[0-9a-f]{64}$")
        self.assertRegex(backup["recovery_proof"], r"^[0-9a-f]{64}$")

    def test_message_length_is_rejected_before_sending(self):
        app = wire.Wire()
        peer = wire.Peer("peer", None, os.urandom(32), os.urandom(32), lambda _: None)
        with self.assertRaises(ValueError):
            app.send_message(peer, "x" * (wire.MAX_MESSAGE_CHARS + 1))

    def test_shutdown_removes_partial_and_temporary_transfers(self):
        app = wire.Wire()
        with tempfile.TemporaryDirectory() as temporary:
            partial = Path(temporary) / ".partial"
            archive = Path(temporary) / "folder.zip"
            partial.write_bytes(b"partial")
            archive.write_bytes(b"temporary archive")
            app.incoming_files["a" * 32] = {"temp": partial}
            app.outgoing_files["b" * 32] = {"path": archive, "cleanup": True}
            app.close()
            self.assertFalse(partial.exists())
            self.assertFalse(archive.exists())

    def test_closed_chat_does_not_fall_back_to_the_only_connected_peer(self):
        source = Path(wire.__file__).read_text(encoding="utf-8")
        self.assertNotIn("if len(app.peers) == 1:", source)


if __name__ == "__main__":
    unittest.main()
