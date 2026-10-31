import unittest

import wire
from test_group_forward_secrecy import PrekeyDirectory


class GroupMessageActionTests(PrekeyDirectory):
    def setUp(self) -> None:
        super().setUp()
        for app in self.apps.values():
            app.group_room = "crew"
        self.apps["bob"].publish_prekeys()
        self.apps["alice"].publish_prekeys()

    def history(self, name: str) -> list[dict]:
        return self.apps[name].read_history("group-crew")

    def send_and_wait(self, sender: str, line: str, receiver: str, count: int) -> None:
        wire.handle_input(self.apps[sender], line)
        self.wait_for(lambda: len(self.history(receiver)) >= count)

    def test_reply_react_edit_delete_reach_the_other_side(self):
        alice, bob = self.apps["alice"], self.apps["bob"]
        self.send_and_wait("alice", "dinner at 7?", "bob", 1)
        original = self.history("bob")[0]["id"]

        wire.handle_input(bob, f"/reply {original[:6]} works for me")
        self.wait_for(lambda: len(self.history("alice")) == 2)
        reply = self.history("alice")[-1]
        self.assertEqual((reply["text"], reply["reply_to"]), ("works for me", original))
        self.assertEqual(self.history("bob")[-1]["text"], "works for me")  # not the wire format

        wire.handle_input(bob, f"/react {original[:6]} +1")
        self.wait_for(lambda: self.history("alice")[0].get("reactions"))
        self.assertEqual(self.history("alice")[0]["reactions"], ["bob:+1"])

        wire.handle_input(alice, f"/edit {original[:6]} dinner at 8?")
        self.wait_for(lambda: self.history("bob")[0]["text"] == "dinner at 8?")
        self.assertTrue(self.history("bob")[0]["edited"])

        wire.handle_input(alice, f"/delete {original[:6]}")
        self.wait_for(lambda: self.history("bob")[0].get("deleted"))
        self.assertEqual(len(self.history("bob")), 2)  # actions never show up as new messages

    def test_you_cannot_edit_or_delete_someone_elses_message(self):
        alice, bob = self.apps["alice"], self.apps["bob"]
        self.send_and_wait("alice", "my words", "bob", 1)
        original = self.history("bob")[0]["id"]
        self.lines = []
        wire.handle_input(bob, f"/edit {original[:6]} your words")  # refused locally
        self.assertEqual(self.history("bob")[0]["text"], "my words")
        bob.send_group_message("crew", f"EDIT {original} forged words", record=False)  # forced over the wire
        bob.send_group_message("crew", f"DELETE {original}", record=False)
        wire.time.sleep(0.5)
        self.assertEqual(self.history("alice")[0]["text"], "my words")
        self.assertFalse(self.history("alice")[0].get("deleted"))


if __name__ == "__main__":
    unittest.main()
