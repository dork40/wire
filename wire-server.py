"""Small username directory and encrypted-packet relay for wire."""

from __future__ import annotations

import base64
import json
import socket
import struct
import threading
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

HOST = os.environ.get("WIRE_HOST", "0.0.0.0")
PORT = int(os.environ.get("WIRE_PORT", "47666"))
SERVER_VERSION = "1.3.1"
DEFAULT_STATE = (Path(sys.executable).parent / "wire-server-data") if getattr(sys, "frozen", False) else Path(__file__).with_name("wire-server-data")
STATE = Path(os.environ.get("WIRE_STATE", str(DEFAULT_STATE)))
USERS_FILE = STATE / "users.json"
GROUPS_FILE = STATE / "groups.json"
LOCK = threading.Lock()
ONLINE: dict[str, tuple[str, socket.socket, str, str]] = {}


def receive_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        piece = sock.recv(count - len(data))
        if not piece:
            raise ConnectionError("connection closed")
        data.extend(piece)
    return bytes(data)


def receive(sock: socket.socket) -> dict:
    size = struct.unpack("!I", receive_exact(sock, 4))[0]
    if size > 1_000_000:
        raise ValueError("packet too large")
    return json.loads(receive_exact(sock, size).decode("utf-8"))


def send(sock: socket.socket, packet: dict) -> None:
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))


def save_users(users: dict) -> None:
    STATE.mkdir(exist_ok=True)
    tmp = USERS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(users, indent=2), encoding="utf-8")
    tmp.replace(USERS_FILE)


def load_groups() -> dict:
    if not GROUPS_FILE.exists():
        return {}
    try:
        loaded = json.loads(GROUPS_FILE.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_groups(groups: dict) -> None:
    STATE.mkdir(exist_ok=True)
    tmp = GROUPS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(groups, indent=2), encoding="utf-8")
    tmp.replace(GROUPS_FILE)


def valid_group_name(value: object) -> bool:
    return isinstance(value, str) and 3 <= len(value) <= 32 and all(char.isalnum() or char in "_-" for char in value)


def group_details(group: dict, users: dict, online: set[str]) -> dict:
    member_keys = [item for item in group.get("members", []) if item in users]
    return {
        "name": group["name"], "owner": group["owner"],
        "members": [{"name": users[item]["name"], "public": users[item]["public"], "online": item in online} for item in member_keys],
    }


def valid_hello(packet: dict) -> tuple[str, str, str] | None:
    name, public, sign_public = packet.get("name"), packet.get("public"), packet.get("sign_public")
    if not isinstance(name, str) or not name.isalnum() or not 3 <= len(name) <= 24 or not isinstance(public, str) or not isinstance(sign_public, str):
        return None
    try:
        if len(base64.b64decode(public.encode("ascii"), validate=True)) != 32 or len(base64.b64decode(sign_public.encode("ascii"), validate=True)) != 32:
            return None
    except Exception:
        return None
    return name, public, sign_public


def login_proof_bytes(name: str, nonce: bytes) -> bytes:
    return b"wire-login-v1\0" + name.lower().encode("utf-8") + b"\0" + nonce


def deliver(username: str, packet: dict) -> bool:
    with LOCK:
        connection = ONLINE.get(username.lower())
    if not connection:
        return False
    try:
        send(connection[1], packet)
        return True
    except OSError:
        return False


def handle(sock: socket.socket, address: tuple[str, int]) -> None:
    key: str | None = None
    try:
        hello = receive(sock)
        if hello.get("type") != "hello" or not (details := valid_hello(hello)):
            send(sock, {"type": "error", "message": "bad login"})
            return
        name, public, sign_public = details
        key = name.lower()
        with LOCK:
            users = load_users()
            known = users.get(key)
            if known and known["public"] != public:
                send(sock, {"type": "error", "message": "username belongs to another identity"})
                return
            if known and known.get("sign_public") and known["sign_public"] != sign_public:
                send(sock, {"type": "error", "message": "username belongs to another identity"})
                return
            if key in ONLINE:
                send(sock, {"type": "error", "message": "username is already online"})
                return
        nonce = os.urandom(32)
        send(sock, {"type": "challenge", "nonce": base64.b64encode(nonce).decode("ascii")})
        proof = receive(sock)
        if proof.get("type") != "prove" or not isinstance(proof.get("signature"), str):
            send(sock, {"type": "error", "message": "login proof missing"})
            return
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(sign_public.encode("ascii"), validate=True)).verify(
                base64.b64decode(proof["signature"].encode("ascii"), validate=True), login_proof_bytes(name, nonce)
            )
        except Exception:
            send(sock, {"type": "error", "message": "login proof failed"})
            return
        with LOCK:
            users = load_users()
            users[key] = {"name": name, "public": public, "sign_public": sign_public}
            save_users(users)
            ONLINE[key] = (name, sock, public, address[0])
        send(sock, {"type": "ready", "name": name, "version": SERVER_VERSION})
        print(f"online  {name}  {address[0]}")

        while True:
            packet = receive(sock)
            kind = packet.get("type")
            if kind == "open":
                target = packet.get("to", "").lower()
                with LOCK:
                    target_info = ONLINE.get(target)
                if not target_info:
                    send(sock, {"type": "error", "message": "user is offline or does not exist"})
                elif target == key:
                    send(sock, {"type": "error", "message": "cannot open a room with yourself"})
                elif deliver(target, {"type": "request", "from": name, "public": public}):
                    send(sock, {"type": "waiting", "to": target_info[0]})
            elif kind == "discover":
                query = packet.get("query", "").lower()
                if not isinstance(query, str):
                    query = ""
                with LOCK:
                    users = load_users()
                    online = set(ONLINE)
                matches = [
                    {"name": account["name"], "online": username in online}
                    for username, account in users.items()
                    if query in account["name"].lower()
                ][:50]
                send(sock, {"type": "discover", "users": matches})
            elif kind == "status":
                requested = packet.get("users", [])
                if not isinstance(requested, list):
                    requested = []
                requested_keys = [item.lower() for item in requested[:100] if isinstance(item, str)]
                with LOCK:
                    users = load_users()
                    online = set(ONLINE)
                matches = [
                    {"name": users[item]["name"], "online": item in online}
                    for item in requested_keys
                    if item in users
                ]
                send(sock, {"type": "status", "users": matches})
            elif kind == "ping":
                send(sock, {"type": "pong", "id": packet.get("id", "")})
            elif kind == "group_create":
                group_name = packet.get("name")
                requested = packet.get("members", [])
                if not valid_group_name(group_name) or not isinstance(requested, list):
                    send(sock, {"type": "error", "message": "invalid group name or members"})
                    continue
                group_key = group_name.lower()
                requested_keys = [item.lower() for item in requested if isinstance(item, str) and item.isalnum()]
                with LOCK:
                    users, groups = load_users(), load_groups()
                    if group_key in groups:
                        send(sock, {"type": "error", "message": "that group already exists"})
                        continue
                    members = list(dict.fromkeys([key] + [item for item in requested_keys if item in users]))
                    groups[group_key] = {"name": group_name, "owner": key, "members": members}
                    save_groups(groups)
                    detail = group_details(groups[group_key], users, set(ONLINE))
                for member_key in members:
                    deliver(member_key, {"type": "group_list", "groups": [detail]})
            elif kind == "group_list":
                with LOCK:
                    users, groups = load_users(), load_groups()
                    details = [group_details(group, users, set(ONLINE)) for group in groups.values() if key in group.get("members", [])]
                send(sock, {"type": "group_list", "groups": details})
            elif kind == "group_add":
                group_key, member = str(packet.get("group", "")).lower(), str(packet.get("member", "")).lower()
                with LOCK:
                    users, groups = load_users(), load_groups()
                    group = groups.get(group_key)
                    if not group or group.get("owner") != key:
                        send(sock, {"type": "error", "message": "only the group owner can add people"})
                        continue
                    if member not in users:
                        send(sock, {"type": "error", "message": "that username does not exist"})
                        continue
                    if member not in group["members"]:
                        group["members"].append(member)
                        save_groups(groups)
                    detail = group_details(group, users, set(ONLINE))
                for member_key in group["members"]:
                    deliver(member_key, {"type": "group_list", "groups": [detail]})
            elif kind == "group_leave":
                group_key = str(packet.get("group", "")).lower()
                with LOCK:
                    users, groups = load_users(), load_groups()
                    group = groups.get(group_key)
                    if not group or key not in group.get("members", []):
                        send(sock, {"type": "error", "message": "you are not in that group"})
                        continue
                    group["members"].remove(key)
                    if not group["members"]:
                        groups.pop(group_key, None)
                    elif group.get("owner") == key:
                        group["owner"] = group["members"][0]
                    save_groups(groups)
                send(sock, {"type": "group_left", "group": group_key})
            elif kind == "group_send":
                group_key, packets = str(packet.get("group", "")).lower(), packet.get("packets")
                with LOCK:
                    group = load_groups().get(group_key)
                    users = load_users()
                if not group or key not in group.get("members", []) or not isinstance(packets, dict):
                    send(sock, {"type": "error", "message": "group message was rejected"})
                    continue
                for member_key in group["members"]:
                    encrypted = packets.get(member_key)
                    if member_key != key and isinstance(encrypted, dict):
                        deliver(member_key, {"type": "group_message", "group": group["name"], "from": name, "public": public, "packet": encrypted})
            elif kind == "direct_offer":
                target = packet.get("to", "").lower()
                port = packet.get("port")
                offer = packet.get("offer")
                with LOCK:
                    target_info = ONLINE.get(target)
                if not target_info or not isinstance(port, int) or not 1 <= port <= 65535 or not isinstance(offer, dict):
                    send(sock, {"type": "error", "message": "direct transfer unavailable"})
                else:
                    deliver(target, {"type": "direct_offer", "from": name, "host": address[0], "port": port, "offer": offer})
            elif kind == "share_offer":
                target = packet.get("to", "").lower()
                offer = packet.get("offer")
                with LOCK:
                    target_info = ONLINE.get(target)
                if not target_info or not isinstance(offer, dict):
                    send(sock, {"type": "error", "message": "screen share unavailable"})
                else:
                    deliver(target, {"type": "share_offer", "from": name, "offer": offer})
            elif kind == "share_answer":
                target = packet.get("to", "").lower()
                answer = packet.get("answer")
                if not isinstance(answer, dict) or not deliver(target, {"type": "share_answer", "from": name, "answer": answer}):
                    send(sock, {"type": "error", "message": "screen-share peer is offline"})
            elif kind == "accept":
                source = packet.get("from", "").lower()
                with LOCK:
                    source_info = ONLINE.get(source)
                if not source_info:
                    send(sock, {"type": "error", "message": "requester is no longer online"})
                else:
                    deliver(source, {"type": "accepted", "name": name, "public": public})
                    send(sock, {"type": "accepted", "name": source_info[0], "public": source_info[2]})
            elif kind == "relay":
                target = packet.get("to", "").lower()
                payload = packet.get("packet")
                if isinstance(payload, dict) and deliver(target, {"type": "relay", "from": name, "packet": payload}):
                    continue
                send(sock, {"type": "error", "message": "person is offline"})
            else:
                send(sock, {"type": "error", "message": "unknown request"})
    except (ConnectionError, OSError, ValueError, json.JSONDecodeError):
        pass
    finally:
        if key:
            with LOCK:
                if ONLINE.get(key, (None, None, None))[1] is sock:
                    ONLINE.pop(key, None)
            print(f"offline  {key}")
        try:
            sock.close()
        except OSError:
            pass


def main() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, PORT))
    listener.listen()
    print(f"wire server v{SERVER_VERSION} listening on TCP {PORT}")
    try:
        while True:
            sock, address = listener.accept()
            threading.Thread(target=handle, args=(sock, address), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()


if __name__ == "__main__":
    main()
