"""Authenticated LAN web console for a self-hosted Wire server."""
from __future__ import annotations

import base64, hashlib, hmac, html, json, os, secrets, socket, struct, threading, time, zipfile
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from cryptography.fernet import Fernet, InvalidToken

STATE = Path(os.environ.get("WIRE_STATE", "/data"))
BACKUPS = Path(os.environ.get("WIRE_BACKUP_DIR", "/backups"))
STARTED = time.time(); SESSION_TTL = 12 * 60 * 60
SESSIONS: dict[str, tuple[str, float]] = {}; ATTEMPTS: dict[str, list[float]] = {}; LOCK = threading.Lock()
TURN_PROBE_HOST = os.environ.get("WIRE_TURN_PROBE_HOST", "").strip()
TURN_PROBE_PORT = int(os.environ.get("WIRE_TURN_PROBE_PORT", "3478"))
MAX_WEB_CONNECTIONS = 32

def load(name, fallback):
    try:
        value = json.loads((STATE / name).read_text(encoding="utf-8"))
        return value if isinstance(value, type(fallback)) else fallback
    except (OSError, ValueError): return fallback

def esc(value): return html.escape(str(value))

def backup_inventory(limit=8):
    """Return recent backup metadata and verify every displayed archive."""
    archives = sorted(BACKUPS.glob("wire-state-*.zip"), key=lambda item: item.stat().st_mtime, reverse=True)
    entries = []
    for latest in archives[:limit]:
        try:
            with zipfile.ZipFile(latest) as archive:
                manifest = json.loads(archive.read("manifest.json"))
                hashes = manifest.get("files") if manifest.get("format") == 1 else None
                if not isinstance(hashes, dict) or not hashes: raise ValueError("invalid manifest")
                for name, expected in hashes.items():
                    if not isinstance(name, str) or not isinstance(expected, str): raise ValueError("invalid checksum")
                    actual = hashlib.sha256(archive.read(f"state/{name}")).hexdigest()
                    if not hmac.compare_digest(actual, expected): raise ValueError("checksum mismatch")
            ok = True
        except (OSError, KeyError, ValueError, zipfile.BadZipFile, json.JSONDecodeError):
            ok = False
        entries.append({"name": latest.name, "ok": ok, "age": max(0, int(time.time() - latest.stat().st_mtime)),
                        "size": latest.stat().st_size})
    return entries

def verify_latest_backup():
    entries = backup_inventory()
    latest = entries[0] if entries else None
    return {"count": len(list(BACKUPS.glob("wire-state-*.zip"))), "ok": bool(latest and latest["ok"]),
            "age": latest["age"] if latest else None, "name": latest["name"] if latest else None}

def turn_reachable(host=None, port=None, timeout=0.6):
    """Probe the configured local Coturn listener with a STUN binding request."""
    host, port = host or TURN_PROBE_HOST, port or TURN_PROBE_PORT
    if not host: return None
    transaction = os.urandom(12)
    request = struct.pack("!HHI12s", 1, 0, 0x2112A442, transaction)
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connection.settimeout(timeout)
    try:
        connection.sendto(request, (host, int(port)))
        response, _ = connection.recvfrom(2048)
        return len(response) >= 20 and response[:2] == b"\x01\x01" and response[8:20] == transaction
    except (OSError, ValueError):
        return False
    finally:
        connection.close()

def server_security_status():
    backup = verify_latest_backup()
    required = ("server-signing-key", "server-certificate.pem", "server-tls-key.pem")
    identity_ok = all((STATE / name).is_file() and (STATE / name).stat().st_size > 0 for name in required)
    return {"identity": identity_ok, "turn": turn_reachable(), "backup": backup}

STYLE = """
:root{--bg:#07090d;--panel:#0d1219;--card:#121922;--line:#252e3b;--text:#f4f7fb;--muted:#8e9aac;--mint:#6ee7c8;--blue:#79a8ff;--danger:#ff8e9a}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% -10%,#173f40,transparent 32%),var(--bg);color:var(--text);font:15px Inter,Segoe UI,system-ui,sans-serif;min-height:100vh}.shell{display:grid;grid-template-columns:250px 1fr;min-height:100vh}aside{border-right:1px solid var(--line);padding:28px 18px;background:#090c11ee;position:sticky;top:0;height:100vh}.brand{font-size:22px;font-weight:900;letter-spacing:.18em;margin:0 10px 36px}.brand i{display:inline-block;width:11px;height:11px;border-radius:50%;background:var(--mint);box-shadow:0 0 22px var(--mint);margin-right:11px}nav{display:grid;gap:6px}nav a{color:var(--muted);padding:12px 14px;border-radius:11px;text-decoration:none}nav a:hover{background:#121a23;color:var(--text)}nav a.on{background:var(--mint);color:#07110f;font-weight:800}.logout{position:absolute;bottom:25px;left:18px;right:18px}main{padding:42px;max-width:1220px;width:100%;margin:auto}header{display:flex;justify-content:space-between;align-items:end;margin-bottom:28px}h1{font-size:32px;margin:0 0 6px}h2{font-size:17px;margin:0 0 17px}.muted,small{color:var(--muted)}.live,.pill{display:inline-flex;border:1px solid #31574e;background:#10221e;color:var(--mint);padding:7px 12px;border-radius:999px;font-weight:700}.pill{padding:4px 9px;font-size:12px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:16px}.card{grid-column:span 4;background:linear-gradient(145deg,#131a23,#0d1218);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 18px 50px #0004}.wide{grid-column:span 8}.full{grid-column:1/-1}.num{font-size:34px;font-weight:850;margin-top:8px}.list-row{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:13px 2px;border-bottom:1px solid #1d2631}.list-row:last-child{border:0}.person{display:flex;align-items:center;gap:13px}.avatar{display:grid;place-items:center;width:40px;height:40px;border-radius:12px;background:#1b2c31;color:var(--mint);font-weight:850}.stack{display:flex;flex-direction:column;gap:3px}.note{color:#b5bfcc;line-height:1.7}.ok{color:var(--mint)}.bad{color:var(--danger)}.metric{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #1d2631}.metric:last-child{border:0}.login{width:min(430px,calc(100% - 32px));margin:12vh auto;padding:36px}.login.card{display:block}label{display:block;color:var(--muted);margin:18px 0 7px}input{width:100%;border:1px solid var(--line);border-radius:11px;padding:13px 14px;background:#090d12;color:var(--text);font:inherit;outline:none}input:focus{border-color:var(--mint)}button{width:100%;margin-top:22px;padding:13px;border:0;border-radius:11px;background:var(--mint);color:#07110f;font-weight:850;font:inherit;cursor:pointer}.error{color:var(--danger);margin-top:16px}.empty{padding:22px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:13px}@media(max-width:780px){.shell{display:block}aside{height:auto;position:static;border-right:0;border-bottom:1px solid var(--line);padding:18px}.brand{margin:0 0 14px}nav{grid-template-columns:repeat(4,1fr)}nav a{text-align:center;padding:10px 4px}.logout{position:static;display:none}main{padding:24px 16px}.card,.wide{grid-column:1/-1}header{align-items:start}.live{font-size:12px}}
"""

def shell(content, title="Wire"):
    return f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title><style>{STYLE}</style></head><body>{content}</body></html>'.encode()

def login_page(error=""):
    message = f'<p class="error">{esc(error)}</p>' if error else ""
    return shell(f'<section class="card login"><div class="brand"><i></i>WIRE</div><h1>Welcome back</h1><p class="muted">Sign in with your existing Wire account.</p><form method="post" action="/login"><label>Username</label><input name="username" minlength="3" maxlength="24" required autocomplete="username"><label>Password</label><input name="password" type="password" required autocomplete="current-password"><button>Sign in</button>{message}</form></section>', "Sign in · Wire")

def verify_account(username, password):
    backup = load("identity-backups.json", {}).get(username.lower())
    if not isinstance(backup, dict): return None
    try:
        # Accounts created before KDF metadata was stored use the client's
        # legacy scrypt parameters. Matching that exact fallback is required:
        # choosing a newer default derives a different key and rejects the
        # user's otherwise-correct password.
        kdf = backup.get("kdf") or {}; n, r, p = int(kdf.get("n", 2**14)), int(kdf.get("r", 8)), int(kdf.get("p", 1))
        if not (2**14 <= n <= 2**20 and 1 <= r <= 32 and 1 <= p <= 16): return None
        salt = base64.b64decode(backup["salt"], validate=True)
        secret = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
        account = json.loads(Fernet(base64.urlsafe_b64encode(secret)).decrypt(backup["ciphertext"].encode()))
        return account if isinstance(account, dict) and str(account.get("name", "")).lower() == username.lower() else None
    except (KeyError, ValueError, TypeError, InvalidToken, json.JSONDecodeError): return None

def allow_attempt(address):
    now = time.monotonic()
    with LOCK:
        recent = [x for x in ATTEMPTS.get(address, []) if now - x < 900]
        if len(recent) >= 8: ATTEMPTS[address] = recent; return False
        recent.append(now); ATTEMPTS[address] = recent; return True

def age_text(seconds):
    if seconds is None: return "never"
    if seconds < 60: return "just now"
    if seconds < 3600: return f"{seconds // 60}m ago"
    if seconds < 86400: return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"

def size_text(size):
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB": return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024

def state_size():
    try: return sum(item.stat().st_size for item in STATE.iterdir() if item.is_file())
    except OSError: return 0

def user_context(username):
    users, groups = load("users.json", {}), load("groups.json", {})
    record = users.get(username, {})
    friends = [item for item in record.get("friends", []) if isinstance(item, str) and item in users]
    memberships = [group for group in groups.values() if isinstance(group, dict) and username in group.get("members", [])]
    return users, groups, record, friends, memberships

def app_page(username, active, title, subtitle, content):
    links = (("overview", "/", "Overview"), ("people", "/people", "People"),
             ("groups", "/groups", "Groups"), ("server", "/server", "Server"))
    nav = "".join(f'<a class="{"on" if active == key else ""}" href="{href}">{label}</a>' for key, href, label in links)
    return shell(f'<div class="shell"><aside><div class="brand"><i></i>WIRE</div><nav>{nav}</nav><a class="logout muted" href="/logout">Sign out</a></aside><main><header><div><h1>{esc(title)}</h1><div class="muted">{esc(subtitle)}</div></div><div class="live">● Connected</div></header>{content}</main></div>', f'{title} · Wire')

def people_rows(friends, users):
    if not friends: return '<div class="empty">No friends yet. Add people from the Wire terminal with <b>/friend username</b>.</div>'
    return "".join(
        f'<div class="list-row"><div class="person"><span class="avatar">{esc(users[key].get("name", key)[:1].upper())}</span>'
        f'<span class="stack"><b>{esc(users[key].get("name", key))}</b><small>Encrypted contact</small></span></div>'
        f'<span class="pill">{"Do not disturb" if users[key].get("dnd") else "Friend"}</span></div>' for key in friends)

def overview_page(username):
    users, groups, record, friends, memberships = user_context(username)
    security, backups = server_security_status(), backup_inventory()
    latest = backups[0] if backups else None
    healthy = security["identity"] and security["turn"] is True and bool(latest and latest["ok"])
    content = f'''<div class="grid">
      <section class="card"><span class="muted">Friends</span><div class="num">{len(friends)}</div><small>trusted contacts</small></section>
      <section class="card"><span class="muted">Groups</span><div class="num">{len(memberships)}</div><small>encrypted rooms</small></section>
      <section class="card"><span class="muted">Server health</span><div class="num {"ok" if healthy else "bad"}">{"Good" if healthy else "Check"}</div><small>{"all local checks pass" if healthy else "open Server for details"}</small></section>
      <section class="card wide"><h2>Recent people</h2>{people_rows(friends[:5], users)}</section>
      <section class="card"><h2>Privacy by design</h2><p class="note">Messages, files, settings, and history stay encrypted. This console displays account metadata and service health—not conversation contents or private keys.</p></section>
      <section class="card full"><h2>Quick start</h2><div class="metric"><span>Open a conversation</span><b>open username</b></div><div class="metric"><span>Send any file or image</span><b>/send path</b></div><div class="metric"><span>Share a screen or application</span><b>/share</b></div></section>
    </div>'''
    return app_page(username, "overview", f'Hello, {record.get("name", username)}', "Your private Wire home", content)

def people_page(username):
    users, groups, record, friends, memberships = user_context(username)
    content = f'<div class="grid"><section class="card full"><h2>Your friends · {len(friends)}</h2>{people_rows(friends, users)}</section></div>'
    return app_page(username, "people", "People", "Contacts trusted by your Wire account", content)

def groups_page(username):
    users, groups, record, friends, memberships = user_context(username)
    rows = []
    for group in sorted(memberships, key=lambda item: str(item.get("name", "")).lower()):
        members = [item for item in group.get("members", []) if item in users]
        role = "Owner" if group.get("owner") == username else "Admin" if username in group.get("admins", []) else "Member"
        owner = users.get(group.get("owner"), {}).get("name", group.get("owner", "Unknown"))
        rows.append(f'<div class="list-row"><div class="stack"><b>{esc(group.get("name", "Unnamed group"))}</b><small>{len(members)} members · owner {esc(owner)} · {len(group.get("pins", []))} pins</small></div><span class="pill">{role}</span></div>')
    group_rows = "".join(rows) if rows else '<div class="empty">No group memberships yet.</div>'
    content = f'<div class="grid"><section class="card full"><h2>Your groups · {len(memberships)}</h2>{group_rows}</section></div>'
    return app_page(username, "groups", "Groups", "Rooms and membership roles", content)

def server_page(username):
    security, backups = server_security_status(), backup_inventory()
    turn = "Reachable" if security["turn"] is True else "Not configured" if security["turn"] is None else "Unreachable"
    backup_rows = "".join(f'<div class="list-row"><span class="stack"><b>{esc(item["name"])}</b><small>{age_text(item["age"])} · {size_text(item["size"])}</small></span><span class="pill {"ok" if item["ok"] else "bad"}">{"Verified" if item["ok"] else "Damaged"}</span></div>' for item in backups)
    content = f'''<div class="grid">
      <section class="card"><span class="muted">Server identity</span><div class="num {"ok" if security["identity"] else "bad"}">{"Protected" if security["identity"] else "Check"}</div></section>
      <section class="card"><span class="muted">TURN listener</span><div class="num {"ok" if security["turn"] is True else "bad"}">{turn}</div></section>
      <section class="card"><span class="muted">State storage</span><div class="num">{size_text(state_size())}</div><small>metadata and ciphertext</small></section>
      <section class="card full"><h2>Backup history</h2>{backup_rows or '<div class="empty">No server backups were found.</div>'}</section>
      <section class="card full"><h2>Security boundaries</h2><div class="metric"><span>Conversation contents</span><b class="ok">End-to-end encrypted</b></div><div class="metric"><span>Identity backup</span><b class="ok">Password encrypted</b></div><div class="metric"><span>Web access</span><b>LAN only</b></div><div class="metric"><span>Web uptime</span><b>{age_text(int(time.time()-STARTED)).removesuffix(' ago')}</b></div></section>
    </div>'''
    return app_page(username, "server", "Server", "Health, backups, and privacy status", content)

class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)
    def session_user(self):
        item = cookies.SimpleCookie(self.headers.get("Cookie", "")).get("wire_session")
        if not item: return None
        with LOCK:
            session = SESSIONS.get(item.value)
            if not session or session[1] < time.time(): SESSIONS.pop(item.value, None); return None
            return session[0]
    def reply(self, code, body, mime="text/html; charset=utf-8", extra=None):
        self.send_response(code); self.send_header("Content-Type", mime); self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items(): self.send_header(key, value)
        self.send_header("X-Frame-Options", "DENY"); self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer"); self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health": self.reply(200, b'{"ok":true,"service":"wire-web"}', "application/json"); return
        if path == "/logout":
            item = cookies.SimpleCookie(self.headers.get("Cookie", "")).get("wire_session")
            if item:
                with LOCK: SESSIONS.pop(item.value, None)
            self.reply(303, b"", "text/plain", {"Location":"/", "Set-Cookie":"wire_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"}); return
        user = self.session_user()
        if not user:
            if path in ("/", "/people", "/groups", "/server"): self.reply(200, login_page()); return
            self.reply(404, b"not found", "text/plain"); return
        pages = {"/": overview_page, "/people": people_page, "/groups": groups_page, "/server": server_page}
        page = pages.get(path)
        if not page: self.reply(404, b"not found", "text/plain"); return
        self.reply(200, page(user))
    def do_POST(self):
        if urlparse(self.path).path != "/login": self.reply(404, b"not found", "text/plain"); return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 4096: raise ValueError
            form = parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
            username, password = form.get("username", [""])[0].strip(), form.get("password", [""])[0]
        except (ValueError, UnicodeDecodeError): self.reply(400, login_page("Invalid request.")); return
        if not allow_attempt(self.client_address[0]): self.reply(429, login_page("Too many attempts. Try again later.")); return
        if not verify_account(username, password): self.reply(401, login_page("Incorrect username or password.")); return
        with LOCK: ATTEMPTS.pop(self.client_address[0], None)
        token = secrets.token_urlsafe(32)
        with LOCK: SESSIONS[token] = (username.lower(), time.time() + SESSION_TTL)
        self.reply(303, b"", "text/plain", {"Location":"/", "Set-Cookie":f"wire_session={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict"})
    def log_message(self, fmt, *args): print("wire-web:", fmt % args, flush=True)

class WireWebServer(ThreadingHTTPServer):
    """Bound concurrent/slow clients so the LAN console cannot exhaust RAM."""
    daemon_threads = True
    block_on_close = False
    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(MAX_WEB_CONNECTIONS)
        super().__init__(address, handler)
    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        super().process_request(request, client_address)
    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

if __name__ == "__main__":
    print("Wire web UI listening on 8097", flush=True)
    # The container must accept traffic from its bridge interface. Host-side
    # exposure is restricted by the TrueNAS port mapping/firewall.
    WireWebServer(("0.0.0.0", 8097), Handler).serve_forever()  # nosec B104
