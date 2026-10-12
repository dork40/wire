import importlib.util
import os
import socket
import threading
import unittest
from pathlib import Path

import wire


def load_server_module():
    path = Path(__file__).parents[1] / "wire-server.py"
    spec = importlib.util.spec_from_file_location("wire_server_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class TransportTests(unittest.TestCase):
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
