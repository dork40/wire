import os
import time
import unittest

import wire
from test_group_files import TwoClientHarness


class PeerKeySwitchTests(unittest.TestCase):
    def test_old_key_only_works_until_the_first_new_key_packet(self):
        old_key, new_key = os.urandom(32), os.urandom(32)
        peer = wire.Peer("bob", None, new_key, os.urandom(32))
        peer.previous_key = old_key

        def sealed(key, text):
            nonce = os.urandom(12)
            return nonce, wire.AESGCM(key).encrypt(nonce, text, b"aad")

        self.assertEqual(peer.decrypt(*sealed(old_key, b"sent before they switched"), b"aad"), b"sent before they switched")
        self.assertEqual(peer.decrypt(*sealed(new_key, b"first session packet"), b"aad"), b"first session packet")
        self.assertIsNone(peer.previous_key)
        with self.assertRaises(wire.InvalidTag):
            peer.decrypt(*sealed(old_key, b"late or forged old-key packet"), b"aad")


class CrossedOffersTests(unittest.TestCase):
    def test_offers_that_cross_in_flight_agree_on_one_key(self):
        static = os.urandom(32)
        app = wire.Wire()
        old_say = wire.say
        wire.say = lambda _line: None
        try:
            a = wire.Peer("bob", None, static, os.urandom(32))
            b = wire.Peer("alice", None, static, os.urandom(32))
            a_out, b_out = [], []
            a.send_control, b.send_control = a_out.append, b_out.append
            app.start_session(a)
            app.start_session(b)                       # both offers sent before either arrives
            first_a, first_b = a_out.pop(0), b_out.pop(0)
            app.complete_session(a, first_b)           # each side answers with an ack...
            app.complete_session(b, first_a)
            app.complete_session(a, b_out.pop(0))      # ...which the already-switched side ignores
            app.complete_session(b, a_out.pop(0))
        finally:
            wire.say = old_say
        self.assertTrue(a.forward_secret and b.forward_secret)
        self.assertEqual(a.key, b.key)
        self.assertNotEqual(a.key, static)
        self.assertEqual(a_out + b_out, [])            # no endless ack ping-pong


class SessionHandshakeTests(TwoClientHarness):
    def open_room(self, app_name: str, other: str) -> "wire.Peer":
        app = self.apps[app_name]
        peer = app.relay_peer(*self.identities[other])
        app.attach(peer)
        return peer

    def test_both_sides_switch_to_the_same_fresh_key(self):
        alice_side = self.open_room("alice", "bob")
        bob_side = self.open_room("bob", "alice")
        static = alice_side.previous_key or alice_side.key
        self.wait_for(lambda: alice_side.forward_secret and bob_side.forward_secret)
        self.assertEqual(alice_side.key, bob_side.key)
        self.assertNotEqual(alice_side.key, static)
        self.assertIsNone(alice_side.session_private)  # ephemeral secret is gone
        self.assertIsNone(bob_side.session_private)

        self.apps["alice"].send_message(alice_side, "hello over the session key")
        self.wait_for(lambda: self.apps["bob"].read_history("alice"))
        self.assertEqual(self.apps["bob"].read_history("alice")[-1]["text"], "hello over the session key")
        self.assertIsNone(bob_side.previous_key)  # identity key no longer accepted

    def test_each_chat_gets_a_different_session_key(self):
        first = self.open_room("alice", "bob")
        other = self.open_room("bob", "alice")
        self.wait_for(lambda: first.forward_secret and other.forward_secret)
        first_key = first.key
        second = self.apps["alice"].relay_peer(*self.identities["bob"])
        second_other = self.apps["bob"].relay_peer(*self.identities["alice"])
        self.apps["alice"].attach(second)
        self.apps["bob"].attach(second_other)
        self.wait_for(lambda: second.forward_secret and second_other.forward_secret)
        self.assertNotEqual(second.key, first_key)

    def test_older_client_that_ignores_session_keys_still_chats(self):
        bob = self.apps["bob"]
        bob.start_session = lambda peer: None
        bob.complete_session = lambda peer, control: None
        alice_side = self.open_room("alice", "bob")
        self.open_room("bob", "alice")
        time.sleep(0.5)
        self.assertFalse(alice_side.forward_secret)
        self.apps["alice"].send_message(alice_side, "still works")
        self.wait_for(lambda: bob.read_history("alice"))
        self.assertEqual(bob.read_history("alice")[-1]["text"], "still works")


if __name__ == "__main__":
    unittest.main()
