"""Ente admin dashboard: read-only overview of the ente and prvtente instances.

Reads each instance's Postgres with a read-only role (SELECT on the few tables/columns
listed in README.md) and decrypts account emails with museum's key.encryption (NaCl
secretbox, as museum does to send emails). Writes nothing anywhere.

Login is Authelia (Traefik forwardAuth on the Ingress); a NetworkPolicy lets only Traefik
reach the pod, so the login can't be skipped.
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

        cur.execute("""select owner_id, count(*), coalesce(sum((info->>'fileSize')::bigint), 0)::bigint,
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


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Ente admin</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cellipse cx='30' cy='42' rx='22' ry='15' fill='%23FFD43B'/%3E%3Ccircle cx='40' cy='22' r='13' fill='%23FFD43B'/%3E%3Cpath d='M51 23c6-1 10 1 11 3-2 2-6 3-11 2z' fill='%23FF922B'/%3E%3Ccircle cx='43' cy='19' r='2.4' fill='%231a1a1a'/%3E%3C/svg%3E">
<style>
:root{--bg:#f4f6f5;--bg2:#ffffff;--card:#ffffff;--fg:#121614;--mut:#68736d;--line:#e3e8e5;--acc:#1db954;--acc2:#0f9d58;--accbg:rgba(29,185,84,.10);--warn:#d97706;--warnbg:rgba(217,119,6,.10);--shadow:0 1px 2px rgba(16,24,20,.04),0 8px 24px rgba(16,24,20,.06)}
@media (prefers-color-scheme:dark){:root{--bg:#0c0f0d;--bg2:#121614;--card:#151a17;--fg:#e9eeeb;--mut:#8d9a93;--line:#232b26;--accbg:rgba(29,185,84,.14);--warnbg:rgba(245,158,11,.14);--warn:#f59e0b;--shadow:0 1px 2px rgba(0,0,0,.3),0 10px 30px rgba(0,0,0,.35)}}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 10% -10%,var(--accbg),transparent 60%),var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",Inter,system-ui,sans-serif;-webkit-font-smoothing:antialiased;min-height:100vh}
.wrap{max-width:1280px;margin:0 auto;padding:24px 20px 48px}
header{display:flex;align-items:center;gap:14px;margin-bottom:22px}
.logo{width:46px;height:46px;flex:none;filter:drop-shadow(0 4px 10px rgba(255,180,0,.25))}
.brand h1{font-size:22px;letter-spacing:-.02em;margin:0;font-weight:700}
.brand h1 span{color:var(--acc)}
.brand .sub{color:var(--mut);font-size:13px}
.spacer{flex:1}
.refresh{display:flex;align-items:center;gap:8px;color:var(--mut);font-size:12px;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--acc);box-shadow:0 0 0 0 rgba(29,185,84,.6);animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(29,185,84,.55)}70%{box-shadow:0 0 0 8px rgba(29,185,84,0)}100%{box-shadow:0 0 0 0 rgba(29,185,84,0)}}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:28px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px 18px;box-shadow:var(--shadow)}
.stat .k{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.stat .v{font-size:26px;font-weight:700;letter-spacing:-.02em;margin-top:2px}
.stat .v small{font-size:13px;color:var(--mut);font-weight:500;margin-left:4px}
.inst{display:flex;align-items:baseline;gap:10px;margin:8px 0 12px}
.inst h2{font-size:17px;margin:0;font-weight:650;letter-spacing:-.01em}
.pill{font-size:12px;color:var(--mut);background:var(--bg2);border:1px solid var(--line);border-radius:99px;padding:2px 10px}
.inst a{color:var(--mut);font-size:12px;text-decoration:none}.inst a:hover{color:var(--acc)}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));margin-bottom:30px}
.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px;box-shadow:var(--shadow);transition:transform .15s ease,box-shadow .15s ease}
.card:hover{transform:translateY(-2px)}
.card.live{border-color:rgba(29,185,84,.55)}
.head{display:flex;align-items:center;gap:12px}
.av{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;font-weight:700;color:#fff;flex:none;font-size:16px}
.who{min-width:0;flex:1}
.email{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.meta{color:var(--mut);font-size:12px}
.status{font-size:12px;border-radius:99px;padding:3px 10px;white-space:nowrap;border:1px solid var(--line);color:var(--mut);display:flex;align-items:center;gap:6px}
.status.on{color:var(--acc2);background:var(--accbg);border-color:transparent;font-weight:600}
@media (prefers-color-scheme:dark){.status.on{color:var(--acc)}}
.store{margin:16px 0 4px;display:flex;justify-content:space-between;font-size:13px}
.store b{font-weight:650}
.bar{height:8px;background:var(--line);border-radius:99px;overflow:hidden}
.bar>div{height:100%;border-radius:99px;background:linear-gradient(90deg,var(--acc2),var(--acc))}
.bar>div.hot{background:linear-gradient(90deg,#f59e0b,#ef4444)}
.mini{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:14px 0}
.mini div{background:var(--bg2);border:1px solid var(--line);border-radius:12px;padding:8px 10px}
.mini .n{font-weight:650;font-size:15px}.mini .l{color:var(--mut);font-size:11px}
.chartlab{display:flex;justify-content:space-between;color:var(--mut);font-size:11px;margin-top:2px}
.sec{display:flex;gap:6px;flex-wrap:wrap;margin:12px 0 4px}
.tag{font-size:11px;border-radius:8px;padding:2px 8px;background:var(--accbg);color:var(--acc2)}
@media (prefers-color-scheme:dark){.tag{color:var(--acc)}}
.tag.warn{background:var(--warnbg);color:var(--warn)}
.devs{margin-top:12px;border-top:1px solid var(--line);padding-top:10px}
.dev{display:flex;align-items:center;gap:10px;padding:5px 0;font-size:13px}
.dev svg{width:16px;height:16px;flex:none;color:var(--mut)}
.dev .nm{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dev .t{color:var(--mut);font-size:12px;white-space:nowrap}
.dev.fresh .t{color:var(--acc2);font-weight:600}
details summary{cursor:pointer;color:var(--mut);font-size:12px;list-style:none;padding-top:4px}
details summary::-webkit-details-marker{display:none}
.err{color:var(--warn)}
.skel{height:260px;border-radius:18px;background:linear-gradient(90deg,var(--card),var(--bg2),var(--card));background-size:200% 100%;animation:sh 1.2s infinite;border:1px solid var(--line)}
@keyframes sh{0%{background-position:200% 0}100%{background-position:-200% 0}}
footer{color:var(--mut);font-size:12px;text-align:center;margin-top:10px}
</style></head><body><div class="wrap">
<header>
<svg class="logo" viewBox="0 0 64 64" aria-hidden="true"><ellipse cx="30" cy="42" rx="22" ry="15" fill="#FFD43B"/><path d="M12 40c4 8 14 11 22 9-10-1-17-5-22-9z" fill="#F5B800"/><circle cx="40" cy="22" r="13" fill="#FFD43B"/><path d="M51 23c6-1 10 1 11 3-2 2-6 3-11 2z" fill="#FF922B"/><circle cx="43" cy="19" r="2.4" fill="#1a1a1a"/><circle cx="43.8" cy="18.3" r=".8" fill="#fff"/></svg>
<div class="brand"><h1>ente <span>admin</span></h1><div class="sub">Self-hosted photo servers · read-only overview</div></div>
<div class="spacer"></div><div class="refresh"><span class="dot"></span><span id="stamp">loading…</span></div>
</header>
<div class="stats" id="stats"></div>
<div id="root"><div class="grid"><div class="skel"></div><div class="skel"></div><div class="skel"></div></div></div>
<footer>File names, types and places are end-to-end encrypted and invisible to the server. Refreshes every 30 s.</footer>
</div>
<script>
const fmtB=b=>{if(!b)return"0 B";const u=["B","KB","MB","GB","TB"];let i=Math.min(Math.floor(Math.log(b)/Math.log(1024)),4);return(b/1024**i).toFixed(i>2?1:0)+" "+u[i]};
const ago=t=>{if(!t)return"never";const s=Date.now()/1000-t;if(s<60)return"just now";if(s<3600)return Math.floor(s/60)+" min ago";if(s<86400)return Math.floor(s/3600)+" h ago";const d=Math.floor(s/86400);return d<60?d+" d ago":new Date(t*1000).toLocaleDateString()};
const day=t=>t?new Date(t*1000).toLocaleDateString(undefined,{year:"numeric",month:"short",day:"numeric"}):"–";
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const hue=s=>{let h=0;for(const c of s)h=(h*31+c.charCodeAt(0))%360;return h};
const ICON={phone:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="2" width="12" height="20" rx="3"/><path d="M11 18h2"/></svg>',
desktop:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
web:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>'};
const kind=d=>/^Web/.test(d)?"web":/Desktop/.test(d)?"desktop":"phone";
function chart(d,days){const m=Math.max(1,...d),w=320,h=54,bw=w/d.length;
return`<svg width="100%" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="uploads per day">`+
d.map((v,i)=>{const bh=v?Math.max(3,v/m*(h-4)):2;return`<rect x="${i*bw+2}" y="${h-bh}" width="${bw-4}" height="${bh}" rx="3" fill="var(--acc)" opacity="${v?(i===d.length-1?1:.55):.15}"><title>${days[i]}: ${v.toLocaleString()} files</title></rect>`}).join("")+`</svg>
<div class="chartlab"><span>${days[0]}</span><span>${d.reduce((a,b)=>a+b,0).toLocaleString()} files in ${d.length} days</span><span>today</span></div>`}
function dev(x){const fresh=x.last_seen&&Date.now()/1000-x.last_seen<600;return`<div class="dev${fresh?" fresh":""}">${ICON[kind(x.device)]}<span class="nm" title="${esc(x.device)}">${esc(x.device)}</span><span class="t">${ago(x.last_seen)}</span></div>`}
function card(u,days){const pct=u.quota?Math.min(100,u.used/u.quota*100):0;const ini=(u.email[0]||"?").toUpperCase();const h=hue(u.email);
const sec=(u.two_factor?'<span class="tag">2FA app</span>':"")+(u.email_mfa?'<span class="tag">email code</span>':"")+(!u.two_factor&&!u.email_mfa?'<span class="tag warn">password only</span>':"");
const devs=u.devices,shown=devs.slice(0,3),rest=devs.slice(3);
return`<div class="card${u.uploading?" live":""}"><div class="head"><div class="av" style="background:linear-gradient(135deg,hsl(${h} 65% 55%),hsl(${(h+40)%360} 65% 45%))">${esc(ini)}</div>
<div class="who"><div class="email" title="${esc(u.email)}">${esc(u.email)}</div><div class="meta">since ${day(u.created)} · id ${u.id}</div></div>
${u.uploading?`<span class="status on"><span class="dot"></span>uploading · ${u.recent} / 5 min</span>`:`<span class="status">seen ${ago(u.last_seen)}</span>`}</div>
<div class="store"><span><b>${fmtB(u.used)}</b> of ${fmtB(u.quota)}</span><span class="meta">${pct.toFixed(1)}%</span></div><div class="bar"><div class="${pct>90?"hot":""}" style="width:${pct}%"></div></div>
<div class="mini"><div><div class="n">${u.files.toLocaleString()}</div><div class="l">files</div></div><div><div class="n">${fmtB(u.bytes)}</div><div class="l">originals</div></div><div><div class="n">${u.albums}</div><div class="l">albums</div></div><div><div class="n">${u.trash}</div><div class="l">in trash</div></div></div>
${chart(u.daily,days)}
<div class="sec">${sec}<span class="tag" style="background:var(--bg2);color:var(--mut);border:1px solid var(--line)">last upload ${ago(u.last_upload)}</span><span class="tag" style="background:var(--bg2);color:var(--mut);border:1px solid var(--line)">plan until ${day(u.expiry)}</span></div>
<div class="devs">${shown.map(dev).join("")||'<div class="meta">no devices</div>'}${rest.length?`<details><summary>+ ${rest.length} older session${rest.length>1?"s":""}</summary>${rest.map(dev).join("")}</details>`:""}</div></div>`}
function stat(k,v,s){return`<div class="stat"><div class="k">${k}</div><div class="v">${v}${s?`<small>${s}</small>`:""}</div></div>`}
async function load(){try{const r=await fetch("api/data",{cache:"no-store"});const d=await r.json();const all=d.instances.flatMap(i=>i.users);
const live=all.filter(u=>u.uploading);
document.getElementById("stats").innerHTML=stat("Accounts",all.length,`on ${d.instances.length} servers`)+stat("Storage used",fmtB(all.reduce((a,u)=>a+u.used,0)))+stat("Files",all.reduce((a,u)=>a+u.files,0).toLocaleString())+stat("Uploading now",live.length,live.length?live.reduce((a,u)=>a+u.recent,0)+" files / 5 min":"idle");
document.getElementById("stamp").textContent="updated "+new Date(d.generated*1000).toLocaleTimeString();
document.getElementById("root").innerHTML=d.instances.map(i=>`<div class="inst"><h2>${esc(i.name)}</h2><span class="pill">${i.users.length} account${i.users.length===1?"":"s"} · ${fmtB(i.users.reduce((a,u)=>a+u.used,0))}</span><a href="${esc(i.url)}" target="_blank" rel="noopener">${esc(i.url.replace("https://",""))} ↗</a></div>`+(i.error?`<div class="card err">Can't read this server: ${esc(i.error)}</div>`:`<div class="grid">${i.users.map(u=>card(u,i.days)).join("")}</div>`)).join("")}
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
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # keep logs quiet: no emails or paths in the log
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
