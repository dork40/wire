"""Authenticated LAN web console for a self-hosted Wire server."""
from __future__ import annotations

import base64, hashlib, html, json, os, secrets, threading, time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from cryptography.fernet import Fernet, InvalidToken

STATE = Path(os.environ.get("WIRE_STATE", "/data"))
BACKUPS = Path(os.environ.get("WIRE_BACKUP_DIR", "/backups"))
STARTED = time.time(); SESSION_TTL = 12 * 60 * 60
SESSIONS: dict[str, tuple[str, float]] = {}; ATTEMPTS: dict[str, list[float]] = {}; LOCK = threading.Lock()

def load(name, fallback):
    try:
        value = json.loads((STATE / name).read_text(encoding="utf-8"))
        return value if isinstance(value, type(fallback)) else fallback
    except (OSError, ValueError): return fallback

def esc(value): return html.escape(str(value))

STYLE = """
:root{--bg:#07090d;--card:#11161e;--line:#242c38;--text:#f5f7fb;--muted:#8995a7;--mint:#6ee7c8;--danger:#ff8e9a}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 70% -20%,#173a3b,transparent 38%),var(--bg);color:var(--text);font:15px Inter,Segoe UI,system-ui,sans-serif;min-height:100vh}.shell{display:grid;grid-template-columns:245px 1fr;min-height:100vh}aside{border-right:1px solid var(--line);padding:28px 18px;background:#090c11dd}.brand{font-size:22px;font-weight:900;letter-spacing:.18em;margin:0 10px 40px}.brand i{display:inline-block;width:11px;height:11px;border-radius:50%;background:var(--mint);box-shadow:0 0 22px var(--mint);margin-right:11px}nav a{display:block;color:var(--muted);padding:12px 14px;margin:5px 0;border-radius:11px;text-decoration:none}nav a.on{background:var(--mint);color:#07110f;font-weight:800}main{padding:42px;max-width:1200px;width:100%;margin:auto}header{display:flex;justify-content:space-between;align-items:end;margin-bottom:28px}h1{font-size:32px;margin:0 0 6px}.muted,small{color:var(--muted)}.live{border:1px solid #31574e;background:#10221e;color:var(--mint);padding:8px 13px;border-radius:999px;font-weight:700}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.card{background:linear-gradient(145deg,#121820,#0d1117);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 18px 50px #0005}.num{font-size:34px;font-weight:850;margin-top:8px}.wide{grid-column:span 2}h2{font-size:17px;margin:0 0 17px}.person{display:flex;align-items:center;gap:13px;padding:11px 3px;border-bottom:1px solid #1d2430}.person:last-child{border:0}.person i{display:grid;place-items:center;width:38px;height:38px;border-radius:12px;background:#1b2c31;color:var(--mint);font-style:normal;font-weight:800}.person span{display:flex;flex-direction:column;gap:3px}.note{color:#b5bfcc;line-height:1.65}.login{width:min(420px,calc(100% - 32px));margin:12vh auto;padding:34px}label{display:block;color:var(--muted);margin:18px 0 7px}input{width:100%;border:1px solid var(--line);border-radius:11px;padding:13px 14px;background:#090d12;color:var(--text);font:inherit;outline:none}input:focus{border-color:var(--mint)}button{width:100%;margin-top:22px;padding:13px;border:0;border-radius:11px;background:var(--mint);color:#07110f;font-weight:850;font:inherit;cursor:pointer}.error{color:var(--danger);margin-top:16px}@media(max-width:720px){.shell{display:block}aside{display:none}main{padding:24px 16px}.grid{grid-template-columns:1fr}.wide{grid-column:auto}}
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
        kdf = backup.get("kdf") or {}; n, r, p = int(kdf.get("n", 2**17)), int(kdf.get("r", 8)), int(kdf.get("p", 1))
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

def dashboard(username):
    users, groups = load("users.json", {}), load("groups.json", {}); record = users.get(username, {})
    friends = [x for x in record.get("friends", []) if isinstance(x, str) and x in users]
    rows = "".join(f'<div class="person"><i>{esc(users[k].get("name", k)[:1].upper())}</i><span><b>{esc(users[k].get("name", k))}</b><small>Friend</small></span></div>' for k in friends) or '<p class="muted">No friends yet.</p>'
    group_count = sum(username in g.get("members", []) for g in groups.values())
    backup_count = len(list(BACKUPS.glob("wire-state-*.zip")))
    return shell(f'<div class="shell"><aside><div class="brand"><i></i>WIRE</div><nav><a class="on" href="/">Overview</a><a href="#people">Friends</a><a href="#server">Server</a><a href="/logout">Sign out</a></nav></aside><main><header><div><h1>Hello, {esc(record.get("name", username))}</h1><div class="muted">Private home service</div></div><div class="live">● Online</div></header><div class="grid"><section class="card"><span class="muted">Friends</span><div class="num">{len(friends)}</div></section><section class="card"><span class="muted">Your groups</span><div class="num">{group_count}</div></section><section class="card"><span class="muted">Backups</span><div class="num">{backup_count}</div></section><section class="card wide" id="people"><h2>Your friends</h2>{rows}</section><section class="card" id="server"><h2>Server</h2><p class="note">Directory, encrypted relay, TURN, and automatic backups are configured.</p><p class="muted">Web uptime: {int(time.time()-STARTED)} seconds</p></section></div></main></div>')

class Handler(BaseHTTPRequestHandler):
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
        self.send_header("X-Frame-Options", "DENY"); self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'"); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health": self.reply(200, b'{"ok":true,"service":"wire-web"}', "application/json"); return
        if path == "/logout":
            item = cookies.SimpleCookie(self.headers.get("Cookie", "")).get("wire_session")
            if item:
                with LOCK: SESSIONS.pop(item.value, None)
            self.reply(303, b"", "text/plain", {"Location":"/", "Set-Cookie":"wire_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"}); return
        if path != "/": self.reply(404, b"not found", "text/plain"); return
        user = self.session_user(); self.reply(200, dashboard(user) if user else login_page())
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
        token = secrets.token_urlsafe(32)
        with LOCK: SESSIONS[token] = (username.lower(), time.time() + SESSION_TTL)
        self.reply(303, b"", "text/plain", {"Location":"/", "Set-Cookie":f"wire_session={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict"})
    def log_message(self, fmt, *args): print("wire-web:", fmt % args, flush=True)

if __name__ == "__main__":
    print("Wire web UI listening on 8097", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8097), Handler).serve_forever()
