"""Small username directory and encrypted-packet relay for wire."""

from __future__ import annotations

import base64
import argparse
import hmac
import hashlib
import json
import socket
import ssl
import struct
import threading
import time
import os
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

HOST = os.environ.get("WIRE_HOST", "0.0.0.0")
PORT = int(os.environ.get("WIRE_PORT", "47666"))
SERVER_VERSION = "1.4.31"
TURN_URLS = [item.strip() for item in os.environ.get("WIRE_TURN_URLS", "").split(",") if item.strip()]
TURN_SECRET = os.environ.get("WIRE_TURN_SECRET", "")
DEFAULT_STATE = (Path(sys.executable).parent / "wire-server-data") if getattr(sys, "frozen", False) else Path(__file__).with_name("wire-server-data")
STATE = Path(os.environ.get("WIRE_STATE", str(DEFAULT_STATE)))
USERS_FILE = STATE / "users.json"
GROUPS_FILE = STATE / "groups.json"
BACKUPS_FILE = STATE / "identity-backups.json"
QUEUES_FILE = STATE / "offline-queue.json"
SYNC_FILE = STATE / "encrypted-sync.json"
BACKUP_DIR = Path(os.environ["WIRE_BACKUP_DIR"]) if os.environ.get("WIRE_BACKUP_DIR") else None
BACKUP_INTERVAL_SECONDS = max(900, int(os.environ.get("WIRE_BACKUP_INTERVAL", "21600")))
BACKUP_RETAIN = max(2, min(365, int(os.environ.get("WIRE_BACKUP_RETAIN", "28"))))
LOCK = threading.Lock()
ONLINE: dict[str, tuple[str, socket.socket, str, str, str]] = {}
# A client can be sent packets by its own handler and by any number of other
# handlers (messages, file relay, group updates).  TCP is a byte stream, so
# concurrent sendall() calls can splice two length-prefixed packets together.
# Keep a small lock per socket so every packet remains one complete frame.
SEND_LOCKS: dict[int, threading.Lock] = {}
SEND_LOCKS_LOCK = threading.Lock()
MAX_RELAY_PACKET_BYTES = 100 * 1024
MAX_CLIENT_FRAME_BYTES = 256 * 1024
MAX_OFFLINE_QUEUE_PACKETS = 250
MAX_OFFLINE_QUEUE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_OFFLINE_QUEUE_BYTES = 512 * 1024 * 1024
MAX_SYNC_MESSAGES_PER_USER = 1000
MAX_SYNC_BLOB_BYTES = 64 * 1024
MAX_SYNC_BYTES_PER_USER = 16 * 1024 * 1024
MAX_SYNC_TOTAL_BYTES = 256 * 1024 * 1024
MAX_GROUP_MEMBERS = 100
RELAY_RATE_BYTES_PER_SECOND = 40 * 1024 * 1024
RELAY_RATE_BURST_BYTES = 64 * 1024 * 1024
RELAY_BUDGETS: dict[str, tuple[float, float]] = {}
MAX_CONNECTIONS = 256
CONNECTION_SLOTS = threading.BoundedSemaphore(MAX_CONNECTIONS)
MAX_CONNECTIONS_PER_IP = 32
IP_CONNECTIONS: dict[str, int] = {}
IP_CONNECTIONS_LOCK = threading.Lock()
RECOVERY_ATTEMPTS: dict[str, list[float]] = {}
RECOVERY_WINDOW_SECONDS = 15 * 60
MAX_RECOVERY_ATTEMPTS = 5
SERVER_KEY_LOCK = threading.Lock()
SERVER_SIGNING_KEY: ed25519.Ed25519PrivateKey | None = None
STARTED_AT = time.time()


def state_file_names() -> tuple[str, ...]:
    return ("users.json", "groups.json", "identity-backups.json", "offline-queue.json",
            "encrypted-sync.json", "server-signing-key", "server-certificate.pem", "server-tls-key.pem")


def create_state_backup() -> Path | None:
    """Write a consistent, checksummed state snapshot and rotate older copies."""
    if BACKUP_DIR is None:
        return None
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    protect_state_path(BACKUP_DIR, directory=True)
    with LOCK:
        files = {name: (STATE / name).read_bytes() for name in state_file_names() if (STATE / name).is_file()}
    created = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    manifest = {"format": 1, "created": created, "server_version": SERVER_VERSION,
                "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    target = BACKUP_DIR / f"wire-state-{created}.zip"
    temp = target.with_suffix(".tmp")
    with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("manifest.json", json.dumps(manifest, separators=(",", ":")))
        for name, data in files.items():
            archive.writestr(f"state/{name}", data)
    protect_state_path(temp)
    temp.replace(target)
    protect_state_path(target)
    for old in sorted(BACKUP_DIR.glob("wire-state-*.zip"), reverse=True)[BACKUP_RETAIN:]:
        try:
            old.unlink()
        except OSError:
            pass
    return target


def verified_backup_files(source: Path) -> dict[str, bytes]:
    """Return verified state bytes without trusting archive paths or metadata."""
    with zipfile.ZipFile(source, "r") as archive:
        if any(info.file_size > 512 * 1024 * 1024 for info in archive.infolist()):
            raise ValueError("backup contains an oversized entry")
        manifest = json.loads(archive.read("manifest.json"))
        hashes = manifest.get("files") if manifest.get("format") == 1 else None
        if not isinstance(hashes, dict) or not hashes:
            raise ValueError("backup manifest is invalid")
        allowed = set(state_file_names())
        if not set(hashes).issubset(allowed):
            raise ValueError("backup contains an unknown state file")
        files = {}
        for name, expected in hashes.items():
            data = archive.read(f"state/{name}")
            if not isinstance(expected, str) or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected):
                raise ValueError(f"backup verification failed for {name}")
            files[name] = data
        return files


def restore_state_backup(source: Path) -> None:
    files = verified_backup_files(source)
    prepare_state()
    for name, data in files.items():
        target = STATE / name
        temp = target.with_suffix(target.suffix + ".restore.tmp")
        temp.write_bytes(data)
        protect_state_path(temp)
        temp.replace(target)
        protect_state_path(target)


def backup_worker() -> None:
    while True:
        try:
            create_state_backup()
        except Exception as exc:
            print(f"backup failed: {exc}", flush=True)
        time.sleep(BACKUP_INTERVAL_SECONDS)


def turn_credentials(name: str) -> dict | None:
    """Create Coturn REST credentials that expire instead of exposing its secret."""
    if (len(TURN_SECRET) < 32 or not TURN_URLS or len(TURN_URLS) > 4
            or any(not url.startswith(("turn:", "turns:")) or len(url) > 300 for url in TURN_URLS)):
        return None
    username = f"{int(time.time()) + 3600}:{name.lower()}"
    credential = base64.b64encode(
        hmac.new(TURN_SECRET.encode("utf-8"), username.encode("utf-8"), hashlib.sha1).digest()
    ).decode("ascii")
    return {"urls": TURN_URLS, "username": username, "credential": credential, "expires_in": 3600}


def protect_state_path(path: Path, directory: bool = False) -> None:
    if os.name == "nt":
        return
    try:
        path.chmod(0o700 if directory else 0o600)
    except OSError:
        pass


def prepare_state() -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    protect_state_path(STATE, directory=True)


def replace_private_json(target: Path, payload: str) -> None:
    prepare_state()
    temp = target.with_suffix(".tmp")
    temp.write_text(payload, encoding="utf-8")
    protect_state_path(temp)
    temp.replace(target)
    protect_state_path(target)


def server_signing_key() -> ed25519.Ed25519PrivateKey:
    global SERVER_SIGNING_KEY
    with SERVER_KEY_LOCK:
        if SERVER_SIGNING_KEY is not None:
            return SERVER_SIGNING_KEY
        prepare_state()
        key_file = STATE / "server-signing-key"
        try:
            raw = base64.b64decode(key_file.read_text(encoding="ascii"), validate=True)
            SERVER_SIGNING_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(raw)
        except (OSError, ValueError):
            SERVER_SIGNING_KEY = ed25519.Ed25519PrivateKey.generate()
            key_file.write_text(base64.b64encode(SERVER_SIGNING_KEY.private_bytes_raw()).decode("ascii"), encoding="ascii")
            protect_state_path(key_file)
        return SERVER_SIGNING_KEY


def tls_context() -> ssl.SSLContext:
    """Create a persistent self-signed TLS identity backed by the server key."""
    prepare_state()
    key = server_signing_key()
    certificate_file, tls_key_file = STATE / "server-certificate.pem", STATE / "server-tls-key.pem"
    if not certificate_file.exists() or not tls_key_file.exists():
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wire Directory")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=3650))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                       .sign(key, algorithm=None))
        tls_key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        certificate_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        protect_state_path(tls_key_file); protect_state_path(certificate_file)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate_file, tls_key_file)
    return context


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
    if size > MAX_CLIENT_FRAME_BYTES:
        raise ValueError("packet too large")
    return json.loads(receive_exact(sock, size).decode("utf-8"))


def send(sock: socket.socket, packet: dict) -> None:
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    framed = struct.pack("!I", len(raw)) + raw
    with SEND_LOCKS_LOCK:
        write_lock = SEND_LOCKS.setdefault(id(sock), threading.Lock())
    with write_lock:
        sock.sendall(framed)


def load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))


def save_users(users: dict) -> None:
    replace_private_json(USERS_FILE, json.dumps(users, indent=2))


def load_groups() -> dict:
    if not GROUPS_FILE.exists():
        return {}
    try:
        loaded = json.loads(GROUPS_FILE.read_text(encoding="utf-8"))
        return loaded if isinstance(loaded, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_groups(groups: dict) -> None:
    replace_private_json(GROUPS_FILE, json.dumps(groups, indent=2))


def load_backups() -> dict:
    try:
        value = json.loads(BACKUPS_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError): return {}


def save_backups(backups: dict) -> None:
    replace_private_json(BACKUPS_FILE, json.dumps(backups))


def load_queues() -> dict:
    try:
        value = json.loads(QUEUES_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError): return {}


def save_queues(queues: dict) -> None:
    replace_private_json(QUEUES_FILE, json.dumps(queues, separators=(",", ":")))


def load_sync() -> dict:
    try:
        value = json.loads(SYNC_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_sync(value: dict) -> None:
    replace_private_json(SYNC_FILE, json.dumps(value, separators=(",", ":")))


def valid_sync_blob(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value.encode("ascii", errors="ignore")) <= MAX_SYNC_BLOB_BYTES


def valid_group_name(value: object) -> bool:
    return isinstance(value, str) and 3 <= len(value) <= 32 and all(char.isalnum() or char in "_-" for char in value)


def group_details(group: dict, users: dict, online: set[str]) -> dict:
    member_keys = [item for item in group.get("members", []) if item in users]
    admins = set(group.get("admins", [group.get("owner")]))
    return {
        "name": group["name"], "owner": group["owner"],
        "pins": [item for item in group.get("pins", []) if isinstance(item, str)][:50],
        "members": [{**signed_identity(users[item]["name"], users[item]["public"], users[item].get("sign_public")), "online": item in online,
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


def directory_proof_bytes(name: str, public: str, sign_public: str, nonce: bytes) -> bytes:
    return (b"wire-directory-v1\0" + name.lower().encode("utf-8") + b"\0"
            + base64.b64decode(public.encode("ascii"), validate=True)
            + base64.b64decode(sign_public.encode("ascii"), validate=True) + nonce)


def directory_identity_bytes(name: str, public: str, sign_public: str) -> bytes:
    return (b"wire-directory-identity-v1\0" + name.lower().encode("utf-8") + b"\0"
            + base64.b64decode(public.encode("ascii"), validate=True)
            + base64.b64decode(sign_public.encode("ascii"), validate=True))


def signed_identity(name: str, public: str, sign_public: str) -> dict:
    if not isinstance(name, str) or not isinstance(public, str) or not isinstance(sign_public, str):
        return {"name": name, "public": public, "sign_public": sign_public, "identity_signature": ""}
    signature = server_signing_key().sign(directory_identity_bytes(name, public, sign_public))
    return {"name": name, "public": public, "sign_public": sign_public,
            "identity_signature": base64.b64encode(signature).decode("ascii")}


def recovery_proof(secret: bytes) -> str:
    """A password-derived proof used only to release the encrypted backup."""
    return hmac.new(secret, b"wire-v1-identity-recovery", hashlib.sha256).hexdigest()


def valid_identity_backup(backup: object) -> bool:
    """Accept current challenge verifiers and legacy proofs, both as SHA-256 hex."""
    if not isinstance(backup, dict):
        return False
    recovery_value = backup.get("recovery_verifier")
    legacy_value = backup.get("recovery_proof")
    valid_recovery = ((isinstance(recovery_value, str) and len(recovery_value) == 64
                       and all(char in "0123456789abcdef" for char in recovery_value))
                      or (isinstance(legacy_value, str) and len(legacy_value) == 64
                          and all(char in "0123456789abcdef" for char in legacy_value)))
    return (isinstance(backup.get("salt"), str)
            and isinstance(backup.get("ciphertext"), str)
            and valid_recovery and len(json.dumps(backup)) <= 20_000)


def allow_recovery(address: str) -> bool:
    """Bound expensive password-recovery guesses by source address."""
    now = time.monotonic()
    with LOCK:
        recent = [stamp for stamp in RECOVERY_ATTEMPTS.get(address, []) if now - stamp < RECOVERY_WINDOW_SECONDS]
        if len(recent) >= MAX_RECOVERY_ATTEMPTS:
            RECOVERY_ATTEMPTS[address] = recent
            return False
        recent.append(now)
        RECOVERY_ATTEMPTS[address] = recent
        return True


def acquire_ip_connection(address: str) -> bool:
    with IP_CONNECTIONS_LOCK:
        current = IP_CONNECTIONS.get(address, 0)
        if current >= MAX_CONNECTIONS_PER_IP:
            return False
        IP_CONNECTIONS[address] = current + 1
        return True


def release_ip_connection(address: str) -> None:
    with IP_CONNECTIONS_LOCK:
        remaining = IP_CONNECTIONS.get(address, 1) - 1
        if remaining > 0:
            IP_CONNECTIONS[address] = remaining
        else:
            IP_CONNECTIONS.pop(address, None)


def packet_size(packet: dict) -> int:
    return len(json.dumps(packet, separators=(",", ":")).encode("utf-8"))


def allow_relay(sender: str, size: int) -> bool:
    """Token bucket: file relay remains fast, but cannot monopolize the server."""
    now = time.monotonic()
    with LOCK:
        tokens, previous = RELAY_BUDGETS.get(sender, (float(RELAY_RATE_BURST_BYTES), now))
        tokens = min(float(RELAY_RATE_BURST_BYTES), tokens + (now - previous) * RELAY_RATE_BYTES_PER_SECOND)
        if size > tokens:
            RELAY_BUDGETS[sender] = (tokens, now)
            return False
        RELAY_BUDGETS[sender] = (tokens - size, now)
        return True


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
    size = packet_size(packet)
    if size > MAX_RELAY_PACKET_BYTES:
        return False
    if deliver(username, packet):
        return True
    key = username.lower()
    with LOCK:
        if key not in load_users():
            return False
        queues = load_queues(); pending = queues.setdefault(key, [])
        total_queued = sum(packet_size(item) for items in queues.values() if isinstance(items, list) for item in items if isinstance(item, dict))
        if total_queued + size > MAX_TOTAL_OFFLINE_QUEUE_BYTES:
            return False
        if len(pending) >= MAX_OFFLINE_QUEUE_PACKETS or sum(packet_size(item) for item in pending if isinstance(item, dict)) + size > MAX_OFFLINE_QUEUE_BYTES:
            return False
        pending.append(packet); save_queues(queues)
    return True


def handle(sock: socket.socket, address: tuple[str, int]) -> None:
    key: str | None = None
    try:
        # Do not let unauthenticated or half-open sockets occupy a worker
        # forever. Authenticated chat connections become idle-friendly below.
        sock.settimeout(15)
        hello = receive(sock)
        # Recovery is a two-step password-proof exchange. The server never
        # releases an encrypted identity blob to an unauthenticated requester.
        if hello.get("type") == "identity_fetch":
            name = hello.get("name", "")
            recovery_key = name.lower() if isinstance(name, str) else ""
            if not allow_recovery(address[0]):
                send(sock, {"type": "error", "message": "identity recovery is temporarily unavailable"})
                return
            with LOCK:
                backup = load_backups().get(recovery_key)
            if (not isinstance(backup, dict) or not isinstance(backup.get("salt"), str)
                    or not isinstance(backup.get("recovery_proof"), str) and not isinstance(backup.get("recovery_verifier"), str)):
                send(sock, {"type": "error", "message": "identity recovery is unavailable"})
                return
            challenge = os.urandom(32)
            response = {"type": "identity_recovery_challenge", "salt": backup["salt"]}
            if isinstance(backup.get("recovery_verifier"), str):
                response.update({"challenge": base64.b64encode(challenge).decode("ascii"), "kdf": backup.get("kdf")})
            send(sock, response)
            proof = receive(sock)
            supplied = proof.get("proof") if proof.get("type") == "identity_fetch_prove" else None
            expected = backup.get("recovery_proof")
            if isinstance(backup.get("recovery_verifier"), str):
                try:
                    verifier = bytes.fromhex(backup["recovery_verifier"])
                    expected = hmac.new(verifier, challenge, hashlib.sha256).hexdigest()
                except ValueError:
                    expected = None
            if not isinstance(supplied, str) or not isinstance(expected, str) or not hmac.compare_digest(supplied, expected):
                send(sock, {"type": "error", "message": "identity recovery is unavailable"})
                return
            send(sock, {"type": "identity_backup", "backup": backup})
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
        directory_key = server_signing_key()
        directory_public = directory_key.public_key().public_bytes_raw()
        directory_signature = directory_key.sign(directory_proof_bytes(name, public, sign_public, nonce))
        send(sock, {"type": "challenge", "nonce": base64.b64encode(nonce).decode("ascii"),
                    "server_sign_public": base64.b64encode(directory_public).decode("ascii"),
                    "server_signature": base64.b64encode(directory_signature).decode("ascii")})
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
            ONLINE[key] = (name, sock, public, address[0], sign_public)
            queues = load_queues()
            queued_packets = queues.pop(key, [])
            if queued_packets: save_queues(queues)
        ready = {"type": "ready", "name": name, "version": SERVER_VERSION,
                 "relay_rate": RELAY_RATE_BYTES_PER_SECOND}
        # Every signed-in Wire identity can use the relay. Security comes from
        # expiring credentials, quotas, and Coturn's private-network blocks,
        # not from limiting normal app features to friends.
        turn = turn_credentials(name)
        if turn:
            ready["turn"] = turn
        send(sock, ready)
        sock.settimeout(None)
        for queued in queued_packets:
            if isinstance(queued, dict): send(sock, queued)
        print(f"online  {name}  {address[0]}")

        command_times: list[float] = []
        while True:
            packet = receive(sock)
            kind = packet.get("type")
            if kind != "relay":
                now = time.monotonic()
                command_times = [stamp for stamp in command_times if now - stamp < 10]
                if len(command_times) >= 500:
                    raise ConnectionError("command rate limit exceeded")
                command_times.append(now)
            if kind == "open":
                target = packet.get("to", "").lower()
                with LOCK:
                    target_info = ONLINE.get(target)
                if not target_info:
                    send(sock, {"type": "error", "message": "user is offline or does not exist"})
                elif target == key:
                    send(sock, {"type": "error", "message": "cannot open a room with yourself"})
                elif deliver(target, {"type": "request", "from": name, **signed_identity(name, public, sign_public)}):
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
            elif kind == "sync_put_settings":
                blob = packet.get("blob")
                if not valid_sync_blob(blob):
                    send(sock, {"type": "error", "message": "invalid encrypted settings sync"}); continue
                with LOCK:
                    synced = load_sync(); account_sync = synced.setdefault(key, {"messages": {}})
                    account_sync["settings"] = blob; save_sync(synced)
                send(sock, {"type": "sync_saved", "kind": "settings"})
            elif kind == "sync_put_message":
                message_id, blob = packet.get("id"), packet.get("blob")
                if not (isinstance(message_id, str) and len(message_id) == 32
                        and all(char in "0123456789abcdef" for char in message_id) and valid_sync_blob(blob)):
                    send(sock, {"type": "error", "message": "invalid encrypted message sync"}); continue
                with LOCK:
                    synced = load_sync(); account_sync = synced.setdefault(key, {"messages": {}})
                    messages = account_sync.setdefault("messages", {})
                    messages[message_id] = blob
                    while (len(messages) > MAX_SYNC_MESSAGES_PER_USER
                           or sum(len(item) for item in messages.values() if isinstance(item, str)) > MAX_SYNC_BYTES_PER_USER):
                        messages.pop(next(iter(messages)))
                    encoded = json.dumps(synced, separators=(",", ":"))
                    if len(encoded.encode("utf-8")) <= MAX_SYNC_TOTAL_BYTES:
                        replace_private_json(SYNC_FILE, encoded)
            elif kind == "sync_fetch":
                with LOCK:
                    account_sync = load_sync().get(key, {})
                    setting_blob = account_sync.get("settings") if valid_sync_blob(account_sync.get("settings")) else None
                    items = [[message_id, blob] for message_id, blob in account_sync.get("messages", {}).items()
                             if isinstance(message_id, str) and valid_sync_blob(blob)]
                if not items:
                    send(sock, {"type": "sync_state", "settings": setting_blob, "messages": [], "done": True})
                else:
                    first = True
                    while items:
                        batch = []
                        while items:
                            trial = batch + [items[0]]
                            candidate = {"type": "sync_state", "settings": setting_blob if first else None,
                                         "messages": trial, "done": False}
                            if batch and packet_size(candidate) > 200 * 1024:
                                break
                            batch.append(items.pop(0))
                        send(sock, {"type": "sync_state", "settings": setting_blob if first else None,
                                    "messages": batch, "done": not items})
                        first = False
            elif kind == "server_stats":
                with LOCK:
                    users, groups, queues = load_users(), load_groups(), load_queues()
                    queued_packets = sum(len(items) for items in queues.values() if isinstance(items, list))
                    status = {"type": "server_stats", "version": SERVER_VERSION, "uptime": int(time.time() - STARTED_AT),
                              "online": len(ONLINE), "accounts": len(users), "groups": len(groups),
                              "queued_packets": queued_packets, "turn": bool(TURN_SECRET and TURN_URLS)}
                send(sock, status)
            elif kind == "identity_backup":
                backup = packet.get("backup")
                if not valid_identity_backup(backup):
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
                requested_keys = [item.lower() for item in requested[:MAX_GROUP_MEMBERS] if isinstance(item, str) and item.isalnum()]
                with LOCK:
                    users, groups = load_users(), load_groups()
                    if group_key in groups:
                        send(sock, {"type": "error", "message": "that group already exists"})
                        continue
                    # Creation is not an implicit membership grant. The same
                    # consent rule applies here as to later group invitations.
                    invitees = list(dict.fromkeys(item for item in requested_keys if item in users and item != key
                                                   and bool(users[item].get("allow_group_invites", True))))
                    groups[group_key] = {"name": group_name, "owner": key, "admins": [key], "members": [key], "invites": invitees, "pins": []}
                    save_groups(groups)
                    detail = group_details(groups[group_key], users, set(ONLINE))
                deliver(key, {"type": "group_list", "groups": [detail]})
                for member_key in invitees:
                    deliver(member_key, {"type": "group_invite", "group": group_name, "from": name})
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
                    if member not in group["members"] and len(group["members"]) >= MAX_GROUP_MEMBERS:
                        send(sock, {"type": "error", "message": f"groups support up to {MAX_GROUP_MEMBERS} members"})
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
                    if member not in group["invites"] and len(group["invites"]) >= MAX_GROUP_MEMBERS:
                        send(sock, {"type": "error", "message": "too many pending group invites"}); continue
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
                    if len(group.get("members", [])) >= MAX_GROUP_MEMBERS:
                        send(sock, {"type": "error", "message": f"groups support up to {MAX_GROUP_MEMBERS} members"}); continue
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
                        deliver_or_queue(member_key, {"type": "group_message", "group": group["name"], "from": name, **signed_identity(name, public, sign_public), "packet": encrypted})
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
                answer, share_id = packet.get("answer"), packet.get("id")
                if not isinstance(answer, dict) or not isinstance(share_id, str) or not deliver(target, {"type": "share_answer", "from": name, "id": share_id, "answer": answer}):
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
                    deliver(source, {"type": "accepted", **signed_identity(name, public, sign_public)})
                    send(sock, {"type": "accepted", **signed_identity(source_info[0], source_info[2], source_info[4])})
            elif kind == "relay":
                target = packet.get("to", "").lower()
                payload = packet.get("packet")
                wrapped = {"type": "relay", "from": name, "packet": payload}
                if not isinstance(payload, dict) or packet_size(wrapped) > MAX_RELAY_PACKET_BYTES:
                    send(sock, {"type": "error", "message": "relay packet is too large"})
                elif not allow_relay(key, packet_size(wrapped)):
                    # The client paces attachment frames.  Silently drop an
                    # unpaced excess frame rather than flooding its terminal.
                    continue
                elif deliver_or_queue(target, wrapped):
                    continue
                else:
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
        with SEND_LOCKS_LOCK:
            SEND_LOCKS.pop(id(sock), None)


def main() -> None:
    parser = argparse.ArgumentParser(description="Wire directory server and state backup utility")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--backup", action="store_true", help="create one verified state backup")
    actions.add_argument("--verify-backup", type=Path, metavar="FILE")
    actions.add_argument("--restore-backup", type=Path, metavar="FILE")
    args = parser.parse_args()
    if args.verify_backup:
        files = verified_backup_files(args.verify_backup)
        print(f"verified Wire backup: {len(files)} state files")
        return
    if args.restore_backup:
        restore_state_backup(args.restore_backup)
        print(f"restored Wire backup: {args.restore_backup}")
        return
    if args.backup:
        target = create_state_backup()
        if target is None:
            raise SystemExit("WIRE_BACKUP_DIR is not configured")
        print(f"created Wire backup: {target}")
        return
    secure_context = tls_context()
    if BACKUP_DIR is not None:
        threading.Thread(target=backup_worker, name="wire-backup", daemon=True).start()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((HOST, PORT))
    listener.listen()
    print(f"wire server v{SERVER_VERSION} listening on TCP {PORT}")
    try:
        while True:
            sock, address = listener.accept()
            if not CONNECTION_SLOTS.acquire(blocking=False):
                sock.close()
                continue
            if not acquire_ip_connection(address[0]):
                sock.close()
                CONNECTION_SLOTS.release()
                continue
            def serve(connection: socket.socket, peer_address: tuple[str, int]) -> None:
                try:
                    connection.settimeout(15)
                    secure = secure_context.wrap_socket(connection, server_side=True)
                    handle(secure, peer_address)
                except (ssl.SSLError, OSError):
                    try:
                        connection.close()
                    except OSError:
                        pass
                finally:
                    release_ip_connection(peer_address[0])
                    CONNECTION_SLOTS.release()
            threading.Thread(target=serve, args=(sock, address), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()


if __name__ == "__main__":
    main()
