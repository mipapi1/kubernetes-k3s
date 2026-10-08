"""Ente admin dashboard: read-only overview of the ente and prvtente instances.

Reads each instance's Postgres with a read-only role (SELECT on the few tables/columns
listed in README.md) and decrypts account emails with museum's key.encryption (NaCl
secretbox, as museum does to send emails). Writes nothing anywhere.

Only listens on 127.0.0.1: oauth2-proxy in the same pod is the only way in.
What Ente can't show by design: file types, names, dates or places (end-to-end
encrypted); the server only knows sizes and when files were added or changed.
"""
import base64
import json
import os
import re
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import nacl.secret
import psycopg

INSTANCES = [
    {"name": "ente", "url": "https://ente.agathla.com", "host": "postgres.ente.svc.cluster.local",
     "password_file": "/secrets/ente-db-password"},
    {"name": "prvtente", "url": "https://prvtente.agathla.com", "host": "postgres.prvtente.svc.cluster.local",
     "password_file": "/secrets/prvtente-db-password"},
]
DB_USER, DB_NAME = "ente_dashboard", "ente_db"
ACTIVE_WINDOW_S = 5 * 60  # "uploading now" = files added in the last 5 minutes
DAYS = 14

with open("/secrets/key-encryption") as f:
    BOX = nacl.secret.SecretBox(base64.b64decode(f.read().strip()))

# Apple model identifiers seen in Ente's user agents -> marketing names
IPHONES = {
    "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro", "iPhone12,5": "iPhone 11 Pro Max",
    "iPhone12,8": "iPhone SE (2nd gen)", "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max", "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13", "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,6": "iPhone SE (3rd gen)", "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max", "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus", "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus", "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max", "iPhone17,5": "iPhone 16e",
}


def device_name(ua):
    """Readable device/app from the user agent Ente stored with the session."""
    ua = ua or ""
    m = re.match(r"^[^/]*/([\d.]+) \((iOS|Android) ([^;]+); [^;]*; ([^;]+);", ua)
    if m:
        version, os_name, os_version, model = m.groups()
        return f"{IPHONES.get(model.strip(), model.strip())} · {os_name} {os_version} · Ente {version}"
    if "Electron" in ua:
        version = re.search(r"ente/([\d.]+)", ua, re.I)
        return "Ente Desktop" + (f" {version.group(1)}" if version else "") + (" · macOS" if "Mac OS" in ua else "")
    if ua.startswith("Mozilla/"):
        browser = next((b for b in ("Firefox", "Edg", "Chrome", "Safari") if b in ua), "Browser")
        os_name = "macOS" if "Mac OS" in ua else "Windows" if "Windows" in ua else "iOS" if "iPhone" in ua else "Linux" if "Linux" in ua else ""
        return f"Web ({'Edge' if browser == 'Edg' else browser}{' · ' + os_name if os_name else ''})"
    return ua[:60] or "unknown"


def decrypt_email(encrypted, nonce):
    try:
        return BOX.decrypt(bytes(encrypted), bytes(nonce)).decode()
    except Exception:
        return "(can't decrypt)"


def us(ts):  # Ente stores microseconds since the epoch
    return ts / 1_000_000 if ts else None


def collect(inst):
    with open(inst["password_file"]) as f:
        password = f.read().strip()
    now = time.time()
    with psycopg.connect(host=inst["host"], dbname=DB_NAME, user=DB_USER, password=password,
                         connect_timeout=5) as conn, conn.cursor() as cur:
        cur.execute("""
            select u.user_id, u.encrypted_email, u.email_decryption_nonce, u.creation_time,
                   u.is_two_factor_enabled, coalesce(u.email_mfa, false),
                   s.storage, s.expiry_time, coalesce(g.storage_consumed, 0)
            from users u
            left join subscriptions s on s.user_id = u.user_id
            left join usage g on g.user_id = u.user_id
            order by u.creation_time""")
        users = {}
        for uid, enc, nonce, created, tfa, emfa, quota, expiry, used in cur.fetchall():
            users[uid] = {"id": uid, "email": decrypt_email(enc, nonce), "created": us(created),
                          "two_factor": tfa, "email_mfa": emfa, "quota": quota or 0,
                          "expiry": us(expiry), "used": used, "files": 0, "bytes": 0,
                          "last_upload": None, "recent": 0, "albums": 0, "trash": 0,
                          "devices": [], "daily": [0] * DAYS}

        cur.execute("""select owner_id, count(*), coalesce(sum((info->>'fileSize')::bigint), 0),
                              max(updation_time),
                              count(*) filter (where updation_time > %s)
                       from files group by owner_id""", (int((now - ACTIVE_WINDOW_S) * 1e6),))
        for uid, n, size, last, recent in cur.fetchall():
            if uid in users:
                users[uid].update(files=n, bytes=size, last_upload=us(last), recent=recent)

        day0 = datetime.fromtimestamp(now, timezone.utc).date().toordinal() - (DAYS - 1)
        cur.execute("""select owner_id, (updation_time / 86400000000)::bigint, count(*) from files
                       where updation_time > %s group by 1, 2""", (int((now - DAYS * 86400) * 1e6),))
        for uid, epoch_day, n in cur.fetchall():
            idx = datetime.fromtimestamp(epoch_day * 86400, timezone.utc).date().toordinal() - day0
            if uid in users and 0 <= idx < DAYS:
                users[uid]["daily"][idx] += n

        cur.execute("select owner_id, count(*) from collections where not is_deleted group by 1")
        for uid, n in cur.fetchall():
            if uid in users:
                users[uid]["albums"] = n
        cur.execute("select user_id, count(*) from trash where not is_deleted and not is_restored group by 1")
        for uid, n in cur.fetchall():
            if uid in users:
                users[uid]["trash"] = n

        cur.execute("""select user_id, app, user_agent, creation_time, last_used_at from tokens
                       where not is_deleted order by last_used_at desc""")
        for uid, app, ua, created, last in cur.fetchall():
            if uid in users:
                users[uid]["devices"].append({"device": device_name(ua), "app": str(app),
                                              "signed_in": us(created), "last_seen": us(last)})

    for u in users.values():
        u["last_seen"] = max((d["last_seen"] or 0 for d in u["devices"]), default=None) or None
        u["uploading"] = u["recent"] > 0
    return {"name": inst["name"], "url": inst["url"], "users": list(users.values()),
            "days": [datetime.fromordinal(day0 + i).strftime("%b %d") for i in range(DAYS)]}


def snapshot():
    out = []
    for inst in INSTANCES:
        try:
            out.append(collect(inst))
        except Exception as e:  # one instance being down must not hide the other
            out.append({"name": inst["name"], "url": inst["url"], "error": str(e)[:300], "users": []})
    return {"generated": time.time(), "instances": out}


PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Ente admin</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#6b7280;--line:#e5e7eb;--acc:#0b7a52;--warn:#b45309;--bar:#16a34a}
@media (prefers-color-scheme:dark){:root{--bg:#111318;--card:#1a1d24;--fg:#e6e8ec;--mut:#9aa1ad;--line:#2a2f3a;--acc:#34d399;--warn:#fbbf24;--bar:#22c55e}}
*{box-sizing:border-box}body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,sans-serif}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:24px 0 8px}.mut{color:var(--mut)}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(330px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.top{display:flex;justify-content:space-between;gap:8px;align-items:baseline}
.email{font-weight:600;word-break:break-all}.badge{font-size:11px;padding:2px 7px;border-radius:99px;border:1px solid var(--line);white-space:nowrap}
.live{color:#fff;background:var(--acc);border-color:var(--acc)}
.meter{height:8px;background:var(--line);border-radius:99px;overflow:hidden;margin:8px 0 4px}.meter>div{height:100%;background:var(--acc)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:2px 12px;margin-top:8px}.kv span:nth-child(odd){color:var(--mut)}
.dev{border-top:1px solid var(--line);margin-top:8px;padding-top:6px;font-size:13px}.dev div{display:flex;justify-content:space-between;gap:8px}
svg{display:block;margin-top:8px}.err{color:var(--warn)}
</style></head><body>
<h1>Ente admin</h1><div class="mut" id="stamp">loading…</div><div id="root"></div>
<script>
const fmtB=b=>{if(!b)return"0 B";const u=["B","KB","MB","GB","TB"];let i=Math.min(Math.floor(Math.log(b)/Math.log(1024)),4);return(b/1024**i).toFixed(i>2?1:0)+" "+u[i]};
const ago=t=>{if(!t)return"never";const s=Date.now()/1000-t;if(s<60)return"just now";if(s<3600)return Math.floor(s/60)+" min ago";if(s<86400)return Math.floor(s/3600)+" h ago";return Math.floor(s/86400)+" d ago"};
const day=t=>t?new Date(t*1000).toLocaleDateString():"–";
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function bars(d,days){const m=Math.max(1,...d),w=300,h=40,bw=w/d.length;return`<svg width="100%" viewBox="0 0 ${w} ${h+12}" preserveAspectRatio="none">`+d.map((v,i)=>`<rect x="${i*bw+1}" y="${h-v/m*h}" width="${bw-2}" height="${v/m*h}" fill="var(--bar)"><title>${days[i]}: ${v}</title></rect>`).join("")+`<text x="0" y="${h+11}" font-size="9" fill="var(--mut)">${days[0]}</text><text x="${w}" y="${h+11}" font-size="9" text-anchor="end" fill="var(--mut)">today</text></svg>`}
function card(u,days){const pct=u.quota?Math.min(100,u.used/u.quota*100):0;
return`<div class="card"><div class="top"><div class="email">${esc(u.email)}</div>${u.uploading?`<span class="badge live">uploading · ${u.recent} in 5 min</span>`:`<span class="badge">seen ${ago(u.last_seen)}</span>`}</div>
<div class="meter"><div style="width:${pct}%"></div></div><div class="mut">${fmtB(u.used)} of ${fmtB(u.quota)} (${pct.toFixed(1)}%)</div>
<div class="kv"><span>Files</span><span>${u.files.toLocaleString()} (${fmtB(u.bytes)})</span><span>Albums</span><span>${u.albums}</span>
<span>In trash</span><span>${u.trash}</span><span>Last upload/change</span><span>${ago(u.last_upload)}</span>
<span>Account since</span><span>${day(u.created)}</span><span>Plan until</span><span>${day(u.expiry)}</span>
<span>Login security</span><span>${u.two_factor?"2FA app":""}${u.two_factor&&u.email_mfa?" + ":""}${u.email_mfa?"email code":""}${!u.two_factor&&!u.email_mfa?"password only":""}</span>
<span>User id</span><span class="mut">${u.id}</span></div>
<div class="mut" style="margin-top:8px">Files added/changed per day (${days.length} days)</div>${bars(u.daily,days)}
<div class="dev"><div class="mut"><b>Devices</b><span>last active</span></div>${u.devices.map(d=>`<div><span>${esc(d.device)}</span><span class="mut">${ago(d.last_seen)}</span></div>`).join("")||'<div class="mut">none</div>'}</div></div>`}
async function load(){try{const r=await fetch("api/data",{cache:"no-store"});const d=await r.json();
document.getElementById("stamp").textContent="updated "+new Date(d.generated*1000).toLocaleTimeString()+" · refreshes every 30 s · file types/names are end-to-end encrypted and not visible to the server";
document.getElementById("root").innerHTML=d.instances.map(i=>`<h2>${esc(i.name)} <span class="mut">· ${i.users.length} users · ${fmtB(i.users.reduce((a,u)=>a+u.used,0))} used</span></h2>`+(i.error?`<div class="card err">Can't read this instance: ${esc(i.error)}</div>`:`<div class="grid">${i.users.map(u=>card(u,i.days)).join("")}</div>`)).join("")}
catch(e){document.getElementById("stamp").textContent="error loading data: "+e}}
load();setInterval(load,30000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?")[0] in ("/", "/index.html"):
            body, ctype = PAGE.encode(), "text/html; charset=utf-8"
        elif self.path.split("?")[0] == "/api/data":
            body, ctype = json.dumps(snapshot()).encode(), "application/json"
        elif self.path == "/healthz":
            body, ctype = b"ok", "text/plain"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # keep logs quiet: no emails or paths in the log
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
