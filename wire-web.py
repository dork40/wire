"""Read-only local web console for a self-hosted Wire server."""
import html, json, os, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

STATE=Path(os.environ.get("WIRE_STATE","/data")); BACKUPS=Path(os.environ.get("WIRE_BACKUP_DIR","/backups")); STARTED=time.time()
def load(name, fallback):
    try:
        value=json.loads((STATE/name).read_text(encoding="utf-8")); return value if isinstance(value,type(fallback)) else fallback
    except (OSError,ValueError): return fallback
def render():
    users=load("users.json",{}); groups=load("groups.json",{})
    rows="".join(f'<div class="person"><i>{html.escape(str(v.get("name",k))[:1].upper())}</i><span><b>{html.escape(str(v.get("name",k)))}</b><small>Wire account</small></span></div>' for k,v in list(users.items())[:50]) or '<p class="muted">No accounts yet.</p>'
    backups=len(list(BACKUPS.glob("wire-state-*.zip")))
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wire</title><style>
:root{{--bg:#07090d;--card:#11161e;--line:#242c38;--text:#f5f7fb;--muted:#8995a7;--mint:#6ee7c8}}*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 70% -20%,#173a3b,transparent 38%),var(--bg);color:var(--text);font:15px Inter,Segoe UI,system-ui,sans-serif;min-height:100vh}}.shell{{display:grid;grid-template-columns:245px 1fr;min-height:100vh}}aside{{border-right:1px solid var(--line);padding:28px 18px;background:#090c11dd}}.brand{{font-size:22px;font-weight:900;letter-spacing:.18em;margin:0 10px 40px}}.brand i{{display:inline-block;width:11px;height:11px;border-radius:50%;background:var(--mint);box-shadow:0 0 22px var(--mint);margin-right:11px}}nav a{{display:block;color:var(--muted);padding:12px 14px;margin:5px 0;border-radius:11px;text-decoration:none}}nav a.on{{background:var(--mint);color:#07110f;font-weight:800}}main{{padding:42px;max-width:1200px;width:100%;margin:auto}}header{{display:flex;justify-content:space-between;align-items:end;margin-bottom:28px}}h1{{font-size:32px;margin:0 0 6px}}.muted,small{{color:var(--muted)}}.live{{border:1px solid #31574e;background:#10221e;color:var(--mint);padding:8px 13px;border-radius:999px;font-weight:700}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}}.card{{background:linear-gradient(145deg,#121820,#0d1117);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 18px 50px #0005}}.num{{font-size:34px;font-weight:850;margin-top:8px}}.wide{{grid-column:span 2}}h2{{font-size:17px;margin:0 0 17px}}.person{{display:flex;align-items:center;gap:13px;padding:11px 3px;border-bottom:1px solid #1d2430}}.person:last-child{{border:0}}.person i{{display:grid;place-items:center;width:38px;height:38px;border-radius:12px;background:#1b2c31;color:var(--mint);font-style:normal;font-weight:800}}.person span{{display:flex;flex-direction:column;gap:3px}}.note{{color:#b5bfcc;line-height:1.65}}@media(max-width:720px){{.shell{{display:block}}aside{{display:none}}main{{padding:24px 16px}}.grid{{grid-template-columns:1fr}}.wide{{grid-column:auto}}}}
</style></head><body><div class="shell"><aside><div class="brand"><i></i>WIRE</div><nav><a class="on" href="/">Overview</a><a href="#people">People</a><a href="#server">Server</a></nav></aside><main><header><div><h1>Your Wire server</h1><div class="muted">192.168.1.199 · Private home service</div></div><div class="live">● Online</div></header><div class="grid"><section class="card"><span class="muted">Accounts</span><div class="num">{len(users)}</div></section><section class="card"><span class="muted">Groups</span><div class="num">{len(groups)}</div></section><section class="card"><span class="muted">Backups</span><div class="num">{backups}</div></section><section class="card wide" id="people"><h2>Wire accounts</h2>{rows}</section><section class="card" id="server"><h2>Server</h2><p class="note">Directory, encrypted relay, TURN, and automatic backups are configured.</p><p class="muted">Web uptime: {int(time.time()-STARTED)} seconds</p></section></div></main></div></body></html>'''.encode()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/api/health": data=b'{"ok":true,"service":"wire-web"}'; mime="application/json"; code=200
        elif path=="/": data=render(); mime="text/html; charset=utf-8"; code=200
        else: data=b"not found"; mime="text/plain"; code=404
        self.send_response(code); self.send_header("Content-Type",mime); self.send_header("Content-Length",str(len(data))); self.send_header("X-Frame-Options","DENY"); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("Content-Security-Policy","default-src 'self'; style-src 'unsafe-inline'"); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(data)
    def log_message(self,fmt,*args): print("wire-web:",fmt%args,flush=True)
if __name__=="__main__":
    print("Wire web UI listening on 8097",flush=True); ThreadingHTTPServer(("0.0.0.0",8097),Handler).serve_forever()
