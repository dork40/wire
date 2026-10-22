import base64
import os
import unittest

import wire
from cryptography.hazmat.primitives.asymmetric import ed25519

from test_group_files import TwoClientHarness
from test_security_fixes import ServerHarness


class PrekeyDirectory(TwoClientHarness):
    """Fake directory that also stores prekeys and relays group messages,
    the way wire-server.py does."""

    def setUp(self) -> None:
        self.prekeys: dict[str, dict] = {}
        self.group_packets: list[dict] = []
        self.hold_group_messages = False
        self.held: list[tuple[str, dict]] = []
        super().setUp()
        for app in self.apps.values():
            app.server_version = "1.4.36"

    def route(self, sender: str, packet: dict) -> None:
        kind = packet.get("type")
        if kind == "prekeys_put":
            self.prekeys[sender] = {"signed": packet["signed"], "one_time": list(packet["one_time"])}
        elif kind == "prekey_fetch":
            bundles = {}
            for name in packet["users"]:
                entry = self.prekeys.get(name)
                if entry:
                    bundles[name] = {"signed": entry["signed"], "one_time": entry["one_time"].pop(0) if entry["one_time"] else None}
            self.apps[sender].server.inbox.put({"type": "prekeys", "id": packet["id"], "bundles": bundles})
        elif kind == "group_send":
            _, public, sign_public, signature = self.identities[sender]
            for name, encrypted in packet["packets"].items():
                self.group_packets.append(encrypted)
                message = {"type": "group_message", "group": packet["group"], "from": sender, "name": sender,
                           "public": public, "sign_public": sign_public, "identity_signature": signature, "packet": encrypted}
                if self.hold_group_messages:
                    self.held.append((name, message))
                else:
                    self.apps[name].server.inbox.put(message)
        else:
            super().route(sender, packet)

    def bob_texts(self) -> list[str]:
        return [record["text"] for record in self.apps["bob"].read_history("group-crew")]


class GroupForwardSecrecyTests(PrekeyDirectory):
    def test_chained_messages_arrive_and_burn_the_one_time_prekey(self):
        alice, bob = self.apps["alice"], self.apps["bob"]
        bob.publish_prekeys()
        before = len(bob.load_ratchets()["prekeys"])
        alice.send_group_message("crew", "first secret")
        alice.send_group_message("crew", "second secret")
        self.wait_for(lambda: len(self.bob_texts()) == 2)
        self.assertEqual(self.bob_texts(), ["first secret", "second secret"])
        self.assertEqual([p["type"] for p in self.group_packets], ["msg2", "msg2"])
        self.assertEqual(len(bob.load_ratchets()["prekeys"]), before - 1)  # used once, then deleted
        self.assertEqual(len(self.prekeys["bob"]["one_time"]), wire.ONE_TIME_PREKEYS_PER_UPLOAD - 1)  # one fetch for both
        state = bob.load_ratchets()["recv"]["alice"]
        self.assertEqual((state["n"], state["skipped"]), (2, {}))  # no old message keys kept

    def test_replayed_packet_is_not_shown_twice(self):
        alice, bob = self.apps["alice"], self.apps["bob"]
        bob.publish_prekeys()
        alice.send_group_message("crew", "only once")
        self.wait_for(lambda: self.bob_texts() == ["only once"])
        _, public, sign_public, signature = self.identities["alice"]
        bob.server.inbox.put({"type": "group_message", "group": "crew", "from": "alice", "public": public,
                              "sign_public": sign_public, "identity_signature": signature, "packet": self.group_packets[0]})
        wire.time.sleep(0.5)
        self.assertEqual(self.bob_texts(), ["only once"])

    def test_out_of_order_delivery_still_decrypts(self):
        alice, bob = self.apps["alice"], self.apps["bob"]
        bob.publish_prekeys()
        self.hold_group_messages = True
        for text in ("one", "two", "three"):
            alice.send_group_message("crew", text)
        for name, message in reversed(self.held):
            self.apps[name].server.inbox.put(message)
        self.wait_for(lambda: len(self.bob_texts()) == 3)
        self.assertEqual(sorted(self.bob_texts()), ["one", "three", "two"])

    def test_falls_back_for_people_without_prekeys(self):
        self.apps["alice"].send_group_message("crew", "hello old client")
        self.wait_for(lambda: self.bob_texts() == ["hello old client"])
        self.assertEqual(self.group_packets[0]["type"], "msg")

    def test_forged_prekey_is_not_trusted(self):
        bob = self.apps["bob"]
        bob.publish_prekeys()
        forged = ed25519.Ed25519PrivateKey.generate()
        for item in [self.prekeys["bob"]["signed"], *self.prekeys["bob"]["one_time"]]:
            item["public"] = wire.b64(os.urandom(32))
            item["signature"] = wire.b64(forged.sign(b"anything"))
        self.apps["alice"].send_group_message("crew", "not to a forged key")
        self.wait_for(lambda: self.bob_texts() == ["not to a forged key"])
        self.assertEqual(self.group_packets[0]["type"], "msg")

    def test_password_change_keeps_the_chain_readable(self):
        alice, bob = self.apps["alice"], self.apps["bob"]
        bob.publish_prekeys()
        alice.send_group_message("crew", "before")
        self.wait_for(lambda: self.bob_texts() == ["before"])
        connection, bob.server = bob.server, None  # offline: no background re-upload during the change
        try:
            bob.change_password("long enough password", "an even longer password")
        finally:
            bob.server = connection
        self.assertEqual(bob.load_ratchets()["recv"]["alice"]["n"], 1)  # chain state survived the re-key
        alice.send_group_message("crew", "after")
        self.wait_for(lambda: self.bob_texts() == ["before", "after"])


class PrekeyServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = ServerHarness()
        self.server = self.harness.server

    def tearDown(self) -> None:
        self.harness.close()

    def prekey(self, owner: str, signer=None) -> dict:
        public = os.urandom(32)
        key_id = os.urandom(8).hex()
        signer = signer or self.harness.signing[owner]
        signature = signer.sign(self.server.prekey_signature_bytes(owner, key_id, public))
        return {"id": key_id, "public": base64.b64encode(public).decode(), "signature": base64.b64encode(signature).decode()}

    def test_upload_fetch_and_one_time_keys_are_handed_out_once(self):
        alice, bob = self.harness.login("alice"), self.harness.login("bob")
        self.server.save_groups({"crew": {"name": "crew", "owner": "alice", "admins": ["alice"], "members": ["alice", "bob"]}})
        first = self.prekey("bob")
        self.server.send(bob, {"type": "prekeys_put", "replace": True, "signed": self.prekey("bob"), "one_time": [first]})
        self.assertEqual(self.server.receive(bob)["one_time"], 1)
        self.server.send(alice, {"type": "prekey_fetch", "id": "r1", "users": ["bob"]})
        self.assertEqual(self.server.receive(alice)["bundles"]["bob"]["one_time"], first)
        self.server.send(alice, {"type": "prekey_fetch", "id": "r2", "users": ["bob"]})
        reply = self.server.receive(alice)["bundles"]["bob"]
        self.assertIsNone(reply["one_time"])  # exhausted: signed key only
        self.assertIsNotNone(reply["signed"])

    def test_prekeys_signed_by_someone_else_are_rejected(self):
        bob = self.harness.login("bob")
        impostor = ed25519.Ed25519PrivateKey.generate()
        self.server.send(bob, {"type": "prekeys_put", "signed": self.prekey("bob", impostor), "one_time": []})
        self.assertEqual(self.server.receive(bob)["type"], "error")

    def test_strangers_cannot_drain_someones_prekeys(self):
        stranger, bob = self.harness.login("stranger"), self.harness.login("bob")
        self.server.send(bob, {"type": "prekeys_put", "replace": True, "signed": self.prekey("bob"), "one_time": [self.prekey("bob")]})
        self.server.receive(bob)
        self.server.send(stranger, {"type": "prekey_fetch", "id": "x", "users": ["bob"]})
        self.assertEqual(self.server.receive(stranger)["bundles"], {})
        self.assertEqual(len(self.server.load_prekeys()["bob"]["one_time"]), 1)


if __name__ == "__main__":
    unittest.main()
