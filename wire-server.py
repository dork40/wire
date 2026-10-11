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
SERVER_VERSION = "1.4.14"
DEFAULT_STATE = (Path(sys.executable).parent / "wire-server-data") if getattr(sys, "frozen", False) else Path(__file__).with_name("wire-server-data")
STATE = Path(os.environ.get("WIRE_STATE", str(DEFAULT_STATE)))
USERS_FILE = STATE / "users.json"
GROUPS_FILE = STATE / "groups.json"
BACKUPS_FILE = STATE / "identity-backups.json"
QUEUES_FILE = STATE / "offline-queue.json"
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


def load_backups() -> dict:
    try:
        value = json.loads(BACKUPS_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError): return {}


def save_backups(backups: dict) -> None:
    STATE.mkdir(exist_ok=True)
    temp = BACKUPS_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(backups), encoding="utf-8")
    temp.replace(BACKUPS_FILE)


def load_queues() -> dict:
    try:
        value = json.loads(QUEUES_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError): return {}


def save_queues(queues: dict) -> None:
    STATE.mkdir(exist_ok=True)
    temp = QUEUES_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(queues, separators=(",", ":")), encoding="utf-8")
    temp.replace(QUEUES_FILE)


def valid_group_name(value: object) -> bool:
    return isinstance(value, str) and 3 <= len(value) <= 32 and all(char.isalnum() or char in "_-" for char in value)


def group_details(group: dict, users: dict, online: set[str]) -> dict:
    member_keys = [item for item in group.get("members", []) if item in users]
    admins = set(group.get("admins", [group.get("owner")]))
    return {
        "name": group["name"], "owner": group["owner"],
        "pins": [item for item in group.get("pins", []) if isinstance(item, str)][:50],
        "members": [{"name": users[item]["name"], "public": users[item]["public"], "online": item in online,
                     "role": "owner" if item == group["owner"] else ("admin" if item in admins else "member")} for item in member_keys],
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


def deliver_or_queue(username: str, packet: dict) -> bool:
    """The directory queues encrypted relay packets only; it cannot read them."""
    if deliver(username, packet):
        return True
    key = username.lower()
    with LOCK:
        if key not in load_users() or len(json.dumps(packet, separators=(",", ":"))) > 100_000:
            return False
        queues = load_queues(); pending = queues.setdefault(key, [])
        if len(pending) >= 1_000:
            return False
        pending.append(packet); save_queues(queues)
    return True


def handle(sock: socket.socket, address: tuple[str, int]) -> None:
    key: str | None = None
    try:
        hello = receive(sock)
        # The blob is encrypted with the user's password before it reaches us.
        # This unauthenticated lookup supports recovery on a new computer.
        if hello.get("type") == "identity_fetch":
            name = hello.get("name", "").lower()
            with LOCK: backup = load_backups().get(name)
            send(sock, {"type": "identity_backup", "backup": backup} if isinstance(backup, dict) else {"type": "error", "message": "no encrypted backup for that user"})
            return
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
            previous = users.get(key, {})
            users[key] = {"name": name, "public": public, "sign_public": sign_public,
                          "allow_group_invites": bool(previous.get("allow_group_invites", True)),
                          "dnd": bool(previous.get("dnd", False)),
                          "friends": [item for item in previous.get("friends", []) if isinstance(item, str)],
                          "friend_requests": [item for item in previous.get("friend_requests", []) if isinstance(item, str)]}
            save_users(users)
            ONLINE[key] = (name, sock, public, address[0])
            queues = load_queues()
            queued_packets = queues.pop(key, [])
            if queued_packets: save_queues(queues)
        send(sock, {"type": "ready", "name": name, "version": SERVER_VERSION})
        for queued in queued_packets:
            if isinstance(queued, dict): send(sock, queued)
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
            elif kind == "friends_list":
                with LOCK:
                    users = load_users(); account = users.get(key, {})
                    friends = [item for item in account.get("friends", []) if item in users]
                    matches = [{"name": users[item]["name"], "online": item in ONLINE,
                                "dnd": bool(users[item].get("dnd", False))} for item in friends]
                    requests = [users[item]["name"] for item in account.get("friend_requests", []) if item in users]
                send(sock, {"type": "friends", "users": matches, "requests": requests})
            elif kind == "friend_request":
                target = str(packet.get("to", "")).lower()
                with LOCK:
                    users = load_users()
                    if target not in users or target == key:
                        send(sock, {"type": "error", "message": "that username cannot be added"}); continue
                    if target in users[key].get("friends", []):
                        send(sock, {"type": "error", "message": "that person is already your friend"}); continue
                    requests = users[target].setdefault("friend_requests", [])
                    if key not in requests: requests.append(key); save_users(users)
                deliver_or_queue(target, {"type": "friend_request", "from": name})
                send(sock, {"type": "friend_request_sent", "to": users[target]["name"]})
            elif kind in ("friend_accept", "friend_decline"):
                target = str(packet.get("from", "")).lower()
                with LOCK:
                    users = load_users()
                    if target not in users or target not in users[key].get("friend_requests", []):
                        send(sock, {"type": "error", "message": "no pending friend request from that person"}); continue
                    users[key]["friend_requests"] = [item for item in users[key]["friend_requests"] if item != target]
                    accepted = kind == "friend_accept"
                    if accepted:
                        for left, right in ((key, target), (target, key)):
                            friends = users[left].setdefault("friends", [])
                            if right not in friends: friends.append(right)
                    save_users(users)
                if accepted:
                    deliver_or_queue(target, {"type": "friend_added", "name": name})
                    send(sock, {"type": "friend_added", "name": users[target]["name"]})
                else:
                    send(sock, {"type": "friend_declined", "name": users[target]["name"]})
            elif kind == "friend_remove":
                target = str(packet.get("name", "")).lower()
                with LOCK:
                    users = load_users()
                    if target not in users or target not in users[key].get("friends", []):
                        send(sock, {"type": "error", "message": "that person is not your friend"}); continue
                    users[key]["friends"] = [item for item in users[key]["friends"] if item != target]
                    users[target]["friends"] = [item for item in users[target].get("friends", []) if item != key]
                    save_users(users)
                deliver_or_queue(target, {"type": "friend_removed", "name": name})
                send(sock, {"type": "friend_removed", "name": users[target]["name"]})
            elif kind == "ping":
                send(sock, {"type": "pong", "id": packet.get("id", "")})
            elif kind == "preferences":
                with LOCK:
                    users = load_users()
                    account = users.get(key)
                    if account is not None:
                        account["allow_group_invites"] = bool(packet.get("allow_group_invites", True))
                        account["dnd"] = bool(packet.get("dnd", False))
                        save_users(users)
            elif kind == "identity_backup":
                backup = packet.get("backup")
                if not isinstance(backup, dict) or not isinstance(backup.get("salt"), str) or not isinstance(backup.get("ciphertext"), str) or len(json.dumps(backup)) > 20000:
                    send(sock, {"type": "error", "message": "invalid encrypted backup"})
                    continue
                with LOCK:
                    backups = load_backups(); backups[key] = backup; save_backups(backups)
                send(sock, {"type": "identity_backup_saved"})
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
                    groups[group_key] = {"name": group_name, "owner": key, "admins": [key], "members": members, "invites": [], "pins": []}
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
                    if not group or key not in group.get("admins", [group.get("owner")]):
                        send(sock, {"type": "error", "message": "only group admins can add people"})
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
            elif kind == "group_invite":
                group_key, member = str(packet.get("group", "")).lower(), str(packet.get("member", "")).lower()
                with LOCK:
                    users, groups = load_users(), load_groups(); group = groups.get(group_key)
                    if not group or key not in group.get("admins", [group.get("owner")]) or member not in users:
                        send(sock, {"type": "error", "message": "group invite was rejected"}); continue
                    if member in group.get("members", []):
                        send(sock, {"type": "error", "message": "that person is already in the group"}); continue
                    if not bool(users[member].get("allow_group_invites", True)):
                        send(sock, {"type": "error", "message": "that person does not allow group invites"}); continue
                    group.setdefault("invites", [])
                    if member not in group["invites"]: group["invites"].append(member); save_groups(groups)
                    inviter = name
                if not deliver(member, {"type": "group_invite", "group": group["name"], "from": inviter}):
                    send(sock, {"type": "error", "message": "invite saved; that person is offline"})
            elif kind == "group_accept_invite":
                group_key = str(packet.get("group", "")).lower()
                with LOCK:
                    users, groups = load_users(), load_groups(); group = groups.get(group_key)
                    if not group or key not in group.get("invites", []):
                        send(sock, {"type": "error", "message": "no pending group invite"}); continue
                    group["invites"].remove(key); group["members"].append(key); save_groups(groups)
                    detail = group_details(group, users, set(ONLINE))
                for member_key in group["members"]: deliver(member_key, {"type": "group_list", "groups": [detail]})
            elif kind == "group_kick":
                group_key, member = str(packet.get("group", "")).lower(), str(packet.get("member", "")).lower()
                with LOCK:
                    users, groups = load_users(), load_groups(); group = groups.get(group_key)
                    if not group or key not in group.get("admins", [group.get("owner")]) or member == group.get("owner") or member not in group.get("members", []):
                        send(sock, {"type": "error", "message": "group removal was rejected"}); continue
                    group["members"].remove(member); group["admins"] = [item for item in group.get("admins", []) if item != member]; save_groups(groups)
                    detail = group_details(group, users, set(ONLINE))
                deliver(member, {"type": "group_kicked", "group": group_key})
                for member_key in group["members"]: deliver(member_key, {"type": "group_list", "groups": [detail]})
            elif kind == "group_admin":
                group_key, member, enabled = str(packet.get("group", "")).lower(), str(packet.get("member", "")).lower(), bool(packet.get("enabled"))
                with LOCK:
                    users, groups = load_users(), load_groups(); group = groups.get(group_key)
                    if not group or group.get("owner") != key or member not in group.get("members", []):
                        send(sock, {"type": "error", "message": "only the group owner can change admins"}); continue
                    admins = set(group.get("admins", [key])); (admins.add(member) if enabled else admins.discard(member)); admins.add(key)
                    group["admins"] = sorted(admins); save_groups(groups); detail = group_details(group, users, set(ONLINE))
                for member_key in group["members"]: deliver(member_key, {"type": "group_list", "groups": [detail]})
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
                        group["owner"] = next((item for item in group.get("admins", []) if item in group["members"]), group["members"][0])
                        group["admins"] = list(dict.fromkeys([group["owner"]] + [item for item in group.get("admins", []) if item in group["members"]]))
                    save_groups(groups)
                send(sock, {"type": "group_left", "group": group_key})
            elif kind in ("group_pin", "group_unpin"):
                group_key, message_id = str(packet.get("group", "")).lower(), packet.get("id")
                with LOCK:
                    users, groups = load_users(), load_groups(); group = groups.get(group_key)
                    if not group or key not in group.get("admins", [group.get("owner")]) or not isinstance(message_id, str) or not 6 <= len(message_id) <= 64:
                        send(sock, {"type": "error", "message": "group pin was rejected"}); continue
                    pins = group.setdefault("pins", [])
                    if kind == "group_pin" and message_id not in pins: pins.append(message_id)
                    if kind == "group_unpin": group["pins"] = [item for item in pins if item != message_id]
                    group["pins"] = group.get("pins", [])[-50:]; save_groups(groups); detail = group_details(group, users, set(ONLINE))
                for member_key in group["members"]: deliver(member_key, {"type": "group_list", "groups": [detail]})
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
                        deliver_or_queue(member_key, {"type": "group_message", "group": group["name"], "from": name, "public": public, "packet": encrypted})
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
            elif kind == "share_stop":
                target, share_id = packet.get("to", "").lower(), packet.get("id")
                if not isinstance(share_id, str) or not deliver(target, {"type": "share_stop", "from": name, "id": share_id}):
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
                if isinstance(payload, dict) and deliver_or_queue(target, {"type": "relay", "from": name, "packet": payload}):
                    continue
                send(sock, {"type": "error", "message": "person is unavailable or their offline queue is full"})
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
