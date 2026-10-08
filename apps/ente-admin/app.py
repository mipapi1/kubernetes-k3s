"""Ente admin dashboard: read-only overview of the ente and prvtente instances.

Reads each instance's Postgres with a read-only role (SELECT on the few tables/columns
listed in README.md) and decrypts account emails with museum's key.encryption (NaCl
secretbox, as museum does to send emails). Writes nothing anywhere.

Login is Authelia (Traefik forwardAuth on the Ingress); a NetworkPolicy lets only Traefik
reach the pod, so the login can't be skipped, and the Remote-User/-Email/-Groups headers
Traefik copies from Authelia's answer can be trusted.

Who sees what: group `admins` sees every account and manages sharing; anyone else sees
the Ente account(s) whose email matches their Authelia email, plus accounts an admin
shared with their username (stored in a small SQLite file on the pod's volume). The
filtering happens here, so a browser never receives accounts it may not see.
What Ente can't show by design: file types, names, dates or places (end-to-end
encrypted); the server only knows sizes and when files were added or changed.
"""
import base64
import json
import os
import re
import sqlite3
import threading
import time
from datetime import datetime
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

# Ente's artwork (apps/ente-admin/media, mounted read-only); served by name only
MEDIA_DIR = "/media"
TYPES = {".png": "image/png", ".webp": "image/webp", ".svg": "image/svg+xml"}
MEDIA = {n: TYPES[os.path.splitext(n)[1]] for n in (os.listdir(MEDIA_DIR) if os.path.isdir(MEDIA_DIR) else [])
         if os.path.splitext(n)[1] in TYPES and not n.startswith(".")}

with open("/secrets/key-encryption") as f:
    BOX = nacl.secret.SecretBox(base64.b64decode(f.read().strip()))

# Sharing: which Authelia user may see which account (besides their own)
GRANTS_DB = os.environ.get("GRANTS_DB", "/data/grants.db")
GRANTS_LOCK = threading.Lock()
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PUBLIC_ORIGIN = "https://ente-admin.agathla.com"


def grants_db():
    conn = sqlite3.connect(GRANTS_DB, timeout=5)
    conn.execute("""create table if not exists grants (
        username text not null, instance text not null, account_id integer not null,
        granted_by text not null, granted_at real not null,
        primary key (username, instance, account_id))""")
    return conn


def load_grants():
    with GRANTS_LOCK, grants_db() as conn:
        return conn.execute("select username, instance, account_id from grants order by username").fetchall()


def change_grant(add, username, instance, account_id, by):
    with GRANTS_LOCK, grants_db() as conn:
        if add:
            conn.execute("insert or ignore into grants values (?, ?, ?, ?, ?)",
                         (username, instance, account_id, by, time.time()))
        else:
            conn.execute("delete from grants where username = ? and instance = ? and account_id = ?",
                         (username, instance, account_id))


DIRECTORY = os.environ.get("DIRECTORY", "/directory/directory.json")


def share_candidates():
    """Authelia users an admin can share with: active, may open this dashboard (group
    app-ente-admin), and not admins (they see everything anyway). From the directory
    synced from Vault (no emails or hashes in it)."""
    try:
        with open(DIRECTORY) as f:
            people = json.load(f)
    except Exception:
        return []
    return sorted(({"user": p["user"], "name": p.get("name") or p["user"]} for p in people
                   if not p.get("disabled") and "app-ente-admin" in p.get("groups", [])
                   and "admins" not in p.get("groups", [])), key=lambda p: p["user"])


def viewer(headers):
    """The logged-in Authelia user, from the headers Traefik copied from Authelia."""
    groups = [g.strip() for g in (headers.get("Remote-Groups") or "").split(",") if g.strip()]
    return {"user": (headers.get("Remote-User") or "").strip().lower(),
            "name": (headers.get("Remote-Name") or "").strip(),
            "email": (headers.get("Remote-Email") or "").strip().lower(),
            "admin": "admins" in groups}


def for_viewer(snap, me):
    """Only the accounts this user may see; admins also get who each account is shared with."""
    grants = load_grants()
    shared = {}
    for username, instance, account_id in grants:
        shared.setdefault((instance, account_id), []).append(username)
    mine = {(i, a) for u, i, a in grants if u == me["user"]}
    out = []
    for inst in snap["instances"]:
        users = []
        for u in inst["users"]:
            own = bool(me["email"]) and u["email"].lower() == me["email"]
            if me["admin"] or own or (inst["name"], u["id"]) in mine:
                u = dict(u, own=own)
                if me["admin"]:
                    u["shared_with"] = shared.get((inst["name"], u["id"]), [])
                users.append(u)
        if users or (me["admin"] and inst.get("error")):
            out.append(dict(inst, users=users))
    result = {"generated": snap["generated"], "instances": out,
              "me": {"user": me["user"], "name": me["name"], "admin": me["admin"]}}
    if me["admin"]:
        result["candidates"] = share_candidates()
    return result


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
                          "devices": [], "daily": [0] * DAYS, "daily_bytes": [0] * DAYS}

        cur.execute("""select owner_id, count(*), coalesce(sum((info->>'fileSize')::bigint), 0)::bigint,
                              max(updation_time),
                              count(*) filter (where updation_time > %s)
                       from files group by owner_id""", (int((now - ACTIVE_WINDOW_S) * 1e6),))
        for uid, n, size, last, recent in cur.fetchall():
            if uid in users:
                users[uid].update(files=n, bytes=size, last_upload=us(last), recent=recent)

        # Per-day counts in local time (TZ of the pod): bucket by hour in SQL, then map each
        # hour to its local calendar day here.
        day0 = datetime.fromtimestamp(now).date().toordinal() - (DAYS - 1)
        cur.execute("""select owner_id, (updation_time / 3600000000)::bigint, count(*),
                              coalesce(sum((info->>'fileSize')::bigint), 0)::bigint
                       from files where updation_time > %s group by 1, 2""",
                    (int((now - (DAYS + 1) * 86400) * 1e6),))
        for uid, epoch_hour, n, size in cur.fetchall():
            idx = datetime.fromtimestamp(epoch_hour * 3600).date().toordinal() - day0
            if uid in users and 0 <= idx < DAYS:
                users[uid]["daily"][idx] += n
                users[uid]["daily_bytes"][idx] += size

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
            "days": [datetime.fromordinal(day0 + i).strftime("%a, %b %-d") for i in range(DAYS)]}


def snapshot():
    out = []
    for inst in INSTANCES:
        try:
            out.append(collect(inst))
        except Exception as e:  # one instance being down must not hide the other
            out.append({"name": inst["name"], "url": inst["url"], "error": str(e)[:300], "users": []})
    return {"generated": time.time(), "instances": out}


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ente admin</title>
<link rel="icon" href="media/auth-ducky.svg" type="image/svg+xml">
<style>
:root{--g:#08c225;--g2:#05a31c;--g3:#0b8f1f;--y:#ffd43b;--bg:#f3f6f3;--bg2:#fbfcfb;--card:#fff;--fg:#111613;--mut:#66726b;--line:#e2e8e4;--accbg:rgba(8,194,37,.10);--warn:#d97706;--warnbg:rgba(217,119,6,.10);--shadow:0 1px 2px rgba(16,24,20,.04),0 10px 30px rgba(16,24,20,.07)}
@media (prefers-color-scheme:dark){:root{--bg:#0b0e0c;--bg2:#121714;--card:#141a16;--fg:#eaf0ec;--mut:#8e9b94;--line:#222b25;--accbg:rgba(8,194,37,.15);--warn:#f59e0b;--warnbg:rgba(245,158,11,.14);--shadow:0 1px 2px rgba(0,0,0,.35),0 12px 32px rgba(0,0,0,.4)}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Rounded","SF Pro Text","Segoe UI",system-ui,sans-serif;-webkit-font-smoothing:antialiased}
.wrap{max-width:1280px;margin:0 auto;padding:20px 20px 40px}
/* hero */
.hero{position:relative;overflow:hidden;border-radius:28px;background:radial-gradient(900px 400px at 85% 30%,#2bd84a 0,transparent 60%),linear-gradient(135deg,var(--g),var(--g2));color:#fff;padding:28px 32px;min-height:220px;display:flex;align-items:center;gap:24px;box-shadow:0 20px 50px rgba(8,194,37,.25)}
.hero:after{content:"";position:absolute;top:-60%;left:0;width:90px;height:220%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.35),transparent);animation:shine 7s ease-in-out infinite;pointer-events:none}
.hero .txt{position:relative;z-index:1;flex:1;min-width:0}
.hero h1{margin:0;font-size:44px;line-height:1;font-weight:850;letter-spacing:-.03em}
.hero h1 .tag{display:inline-block;background:#fff;color:var(--g2);font-size:22px;padding:4px 14px;border-radius:14px;vertical-align:middle;margin-left:8px;transform:rotate(-3deg);animation:rot5 4s ease-in-out infinite}
.hero p{margin:10px 0 16px;opacity:.92;font-size:15px}
.chips{display:flex;gap:8px;flex-wrap:wrap}
.chip{background:rgba(0,0,0,.18);backdrop-filter:blur(4px);border-radius:99px;padding:5px 12px;font-size:12.5px;font-weight:600;display:flex;align-items:center;gap:6px}
.art{position:relative;width:300px;height:220px;flex:none;display:grid;place-items:center}
.rays{position:absolute;width:420px;height:420px;border-radius:50%;background:repeating-conic-gradient(rgba(255,212,59,.35) 0 8deg,transparent 8deg 22deg);-webkit-mask:radial-gradient(circle,#000 20%,transparent 68%);mask:radial-gradient(circle,#000 20%,transparent 68%);animation:spin360 40s linear infinite}
.duck{position:relative;width:270px;filter:drop-shadow(0 14px 18px rgba(0,0,0,.25));animation:flex 3.2s ease-in-out infinite;transform-origin:50% 90%;cursor:pointer}
.duck:hover{animation:rot5 .6s ease-in-out infinite}
/* ticker */
.ticker{margin:14px 0 22px;border-radius:16px;background:var(--card);border:1px solid var(--line);overflow:hidden;box-shadow:var(--shadow);-webkit-mask:linear-gradient(90deg,transparent,#000 6%,#000 94%,transparent);mask:linear-gradient(90deg,transparent,#000 6%,#000 94%,transparent)}
.track{display:flex;width:max-content;animation:scroll 45s linear infinite}
.ticker:hover .track{animation-play-state:paused}
.item{display:flex;align-items:center;gap:8px;padding:11px 26px;white-space:nowrap;font-size:13px;border-right:1px solid var(--line)}
.item b{font-weight:650}.item .m{color:var(--mut)}
/* stats */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-bottom:28px}
.stat{position:relative;overflow:hidden;background:var(--card);border:1px solid var(--line);border-radius:20px;padding:18px 20px;box-shadow:var(--shadow);min-height:118px}
.stat .k{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.07em;font-weight:600}
.stat .v{font-size:30px;font-weight:800;letter-spacing:-.03em;margin-top:4px}
.stat .s{color:var(--mut);font-size:12.5px}
.stat img{position:absolute;right:-6px;bottom:-8px;height:96px;opacity:.95;transition:transform .3s}
.stat:hover img{transform:rotate(-4deg) scale(1.05)}
.stat.go img{animation:rot5 1s ease-in-out infinite}
.stat.go{border-color:rgba(8,194,37,.5)}
/* sections and cards */
.inst{display:flex;align-items:center;gap:10px;margin:6px 0 14px;flex-wrap:wrap}
.inst h2{font-size:19px;margin:0;font-weight:800;letter-spacing:-.02em}
.pill{font-size:12px;color:var(--mut);background:var(--card);border:1px solid var(--line);border-radius:99px;padding:3px 11px}
.inst a{color:var(--mut);font-size:12px;text-decoration:none}.inst a:hover{color:var(--g)}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));margin-bottom:32px}
.card{position:relative;overflow:hidden;background:var(--card);border:1px solid var(--line);border-radius:22px;padding:18px;box-shadow:var(--shadow);transition:transform .2s ease,box-shadow .2s ease}
.card:hover{transform:translateY(-3px)}
.card.enter{animation:slidein .7s cubic-bezier(.2,.8,.2,1) both}
.card.live{border-color:rgba(8,194,37,.6)}
.card.live:after{content:"";position:absolute;top:-50%;left:0;width:70px;height:200%;background:linear-gradient(90deg,transparent,rgba(8,194,37,.18),transparent);animation:shine 4s ease-in-out infinite;pointer-events:none}
.head{display:flex;align-items:center;gap:12px}
.av{width:42px;height:42px;border-radius:14px;display:grid;place-items:center;font-weight:800;color:#fff;flex:none;font-size:17px}
.who{min-width:0;flex:1}.email{font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.meta{color:var(--mut);font-size:12px}
.status{font-size:12px;border-radius:99px;padding:4px 10px;white-space:nowrap;border:1px solid var(--line);color:var(--mut);display:flex;align-items:center;gap:6px}
.status.on{color:#fff;background:var(--g);border-color:transparent;font-weight:650}
.dot{width:8px;height:8px;border-radius:50%;background:currentColor;animation:pulse 1.6s infinite}
.store{margin:16px 0 6px;display:flex;justify-content:space-between;font-size:13px}.store b{font-weight:700}
.bar{height:10px;background:var(--line);border-radius:99px;overflow:hidden}
.bar>div{height:100%;border-radius:99px;background:linear-gradient(90deg,var(--g3),var(--g));transition:width 1s cubic-bezier(.2,.8,.2,1)}
.bar>div.hot{background:linear-gradient(90deg,#f59e0b,#ef4444)}
.mini{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:14px 0}
.mini div{background:var(--bg2);border:1px solid var(--line);border-radius:14px;padding:8px 10px}
.mini .n{font-weight:750;font-size:15px}.mini .l{color:var(--mut);font-size:11px}
.ch{margin-top:2px}
.chhead{display:flex;justify-content:space-between;align-items:baseline;font-size:11.5px;color:var(--mut);margin-bottom:6px}
.chhead b{color:var(--fg);font-weight:650}
.bars{display:flex;align-items:flex-end;gap:4px;height:58px}
.bars .b{flex:1;height:100%;display:flex;align-items:flex-end;cursor:pointer;border-radius:6px;outline:none}
.bars .b i{display:block;width:100%;border-radius:5px;background:var(--g);opacity:.5;transition:opacity .15s,transform .15s;transform-origin:bottom}
.bars .b.zero i{opacity:.14}.bars .b.today i{opacity:1}
.bars .b:hover i,.bars .b:focus i,.bars .b.sel i{opacity:1;transform:scaleY(1.06);box-shadow:0 0 0 2px var(--accbg)}
.chartlab{display:flex;justify-content:space-between;color:var(--mut);font-size:11px;margin-top:4px}
#tip{position:fixed;z-index:50;pointer-events:none;background:var(--fg);color:var(--bg);border-radius:10px;padding:7px 10px;font-size:12px;line-height:1.35;box-shadow:0 8px 24px rgba(0,0,0,.25);opacity:0;transform:translate(-50%,-110%) scale(.96);transition:opacity .12s,transform .12s;white-space:nowrap}
#tip.on{opacity:1;transform:translate(-50%,-115%) scale(1)}
#tip b{font-weight:700}
.sec{display:flex;gap:6px;flex-wrap:wrap;margin:12px 0 4px}
.tag2{font-size:11px;border-radius:8px;padding:2px 8px;background:var(--accbg);color:var(--g3);font-weight:600}
@media (prefers-color-scheme:dark){.tag2{color:#3ee05a}}
.tag2.warn{background:var(--warnbg);color:var(--warn)}.tag2.plain{background:var(--bg2);color:var(--mut);border:1px solid var(--line);font-weight:500}
.devs{margin-top:12px;border-top:1px solid var(--line);padding-top:10px}
.dev{display:flex;align-items:center;gap:10px;padding:5px 0;font-size:13px}
.dev svg{width:16px;height:16px;flex:none;color:var(--mut)}
.dev .nm{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dev .t{color:var(--mut);font-size:12px;white-space:nowrap}.dev.fresh .t{color:var(--g);font-weight:700}
details summary{cursor:pointer;color:var(--mut);font-size:12px;list-style:none;padding-top:4px}
details summary::-webkit-details-marker{display:none}
.oops{display:flex;align-items:center;gap:16px}.oops img{height:90px}
.skel{height:280px;border-radius:22px;background:linear-gradient(90deg,var(--card),var(--bg2),var(--card));background-size:200% 100%;animation:sk 1.2s infinite;border:1px solid var(--line)}
footer{display:flex;align-items:center;justify-content:center;gap:12px;color:var(--mut);font-size:12.5px;margin-top:6px}
footer img{height:56px;animation:flex 4s ease-in-out infinite}
@keyframes shine{0%{transform:translateX(-120px) rotate(25deg)}25%{transform:translateX(1400px) rotate(25deg)}100%{transform:translateX(1400px) rotate(25deg)}}
@keyframes spin360{to{transform:rotate(360deg)}}
@keyframes flex{0%,100%{transform:rotateY(0) translateY(0)}50%{transform:rotateY(15deg) translateY(-6px)}}
@keyframes rot5{0%,100%{transform:rotate(0)}25%{transform:rotate(5deg)}75%{transform:rotate(-5deg)}}
@keyframes slidein{0%{opacity:0;transform:translateY(18px)}100%{opacity:1;transform:none}}
@keyframes scroll{to{transform:translateX(-50%)}}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(255,255,255,.7)}70%{box-shadow:0 0 0 7px rgba(255,255,255,0)}100%{box-shadow:0 0 0 0 rgba(255,255,255,0)}}
@keyframes sk{0%{background-position:200% 0}100%{background-position:-200% 0}}
.me{position:absolute;top:16px;right:18px;z-index:5}
.mebtn{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.28);color:#fff;border-radius:99px;padding:4px 10px 4px 4px;font:inherit;font-size:13px;font-weight:650;cursor:pointer;backdrop-filter:blur(8px);transition:background .15s}
.mebtn:hover,.mebtn[aria-expanded="true"]{background:rgba(255,255,255,.26)}
.meav{width:28px;height:28px;border-radius:50%;display:grid;place-items:center;background:#fff;color:var(--g2);font-weight:800;font-size:13px}
.chev{width:14px;height:14px;opacity:.85;transition:transform .2s}.mebtn[aria-expanded="true"] .chev{transform:rotate(180deg)}
.menu{position:absolute;right:0;top:calc(100% + 8px);min-width:230px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:16px;box-shadow:0 18px 40px rgba(0,0,0,.18);padding:8px;transform-origin:top right;animation:pop .14s ease-out}
.menu[hidden]{display:none}
.mhead{display:flex;align-items:center;gap:10px;padding:8px 8px 10px;border-bottom:1px solid var(--line);margin-bottom:6px}
.mhead .meav{background:linear-gradient(135deg,var(--g),var(--g2));color:#fff;width:36px;height:36px;font-size:15px}
.mhead b{display:block;font-size:14px}.mhead span{color:var(--mut);font-size:12px}
.role{display:inline-block;margin-top:2px;font-size:10.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;border-radius:6px;padding:1px 6px;background:var(--accbg);color:var(--g3)}
@media (prefers-color-scheme:dark){.role{color:#3ee05a}}
.mitem{display:flex;align-items:center;gap:10px;width:100%;padding:9px 10px;border-radius:10px;color:var(--fg);text-decoration:none;font-size:13.5px;font-weight:600}
.mitem svg{width:16px;height:16px;color:var(--mut)}
.mitem:hover,.mitem:focus{background:var(--bg2);outline:none}.mitem.out:hover{color:#ef4444}.mitem.out:hover svg{color:#ef4444}
@keyframes pop{from{opacity:0;transform:scale(.96) translateY(-4px)}to{opacity:1;transform:none}}
.share{margin-top:10px;padding-top:10px;border-top:1px dashed var(--line);display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-size:12px;color:var(--mut)}
.sh{display:inline-flex;align-items:center;gap:4px;background:var(--bg2);border:1px solid var(--line);color:var(--fg);border-radius:99px;padding:2px 4px 2px 9px;font-weight:600}
.sh button,.addsh,.shf button{font:inherit;cursor:pointer;border:0;border-radius:99px}
.sh button{background:transparent;color:var(--mut);padding:0 5px}.sh button:hover{color:#ef4444}
.addsh{background:var(--accbg);color:var(--g3);padding:3px 10px;font-weight:700}
@media (prefers-color-scheme:dark){.addsh{color:#3ee05a}}
.shf{display:inline-flex;gap:4px}.shf select{font:inherit;max-width:200px;border:1px solid var(--line);background:var(--bg2);color:var(--fg);border-radius:99px;padding:3px 10px;outline:none}
.shf select:focus{border-color:var(--g)}.shf .hint{font-size:11.5px}.shf button{background:var(--g);color:#fff;padding:3px 10px;font-weight:700}
.ownb{font-size:11px;font-weight:700;color:var(--g3);background:var(--accbg);border-radius:6px;padding:1px 6px;margin-left:6px}
@media (prefers-color-scheme:dark){.ownb{color:#3ee05a}}
.empty{display:flex;align-items:center;gap:20px;background:var(--card);border:1px solid var(--line);border-radius:22px;padding:24px;box-shadow:var(--shadow)}.empty img{height:120px}
@media (max-width:720px){.art{display:none}.hero h1{font-size:36px}.me{top:12px;right:12px}.mebtn .nm{display:none}}
@media (prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}}
</style></head><body><div class="wrap">
<section class="hero">
<div class="me" id="me" hidden></div>
<div class="txt"><h1>ente<span class="tag">admin</span></h1><p id="sub">Your self-hosted photo servers, at a glance. Read-only, refreshed every 30 seconds.</p>
<div class="chips" id="chips"><span class="chip">loading…</span></div></div>
<div class="art"><div class="rays"></div><img class="duck" src="media/ducky.png" alt="ente duck"></div>
</section>
<div class="ticker"><div class="track" id="track"></div></div>
<div class="stats" id="stats"></div>
<div id="tip" role="tooltip"></div>
<div id="root"><div class="grid"><div class="skel"></div><div class="skel"></div><div class="skel"></div></div></div>
<footer><img src="media/auth-ducky.svg" alt=""><span>Photos, names, places and file types are end-to-end encrypted, so the server (and this page) never sees them.</span></footer>
</div>
<script>
const fmtB=b=>{if(!b)return"0 B";const u=["B","KB","MB","GB","TB"];let i=Math.min(Math.floor(Math.log(b)/Math.log(1024)),4);return(b/1024**i).toFixed(i>2?1:0)+" "+u[i]};
const ago=t=>{if(!t)return"never";const s=Date.now()/1000-t;if(s<60)return"just now";if(s<3600)return Math.floor(s/60)+" min ago";if(s<86400)return Math.floor(s/3600)+" h ago";const d=Math.floor(s/86400);return d<60?d+" d ago":new Date(t*1000).toLocaleDateString()};
const day=t=>t?new Date(t*1000).toLocaleDateString(undefined,{year:"numeric",month:"short",day:"numeric"}):"–";
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const hue=s=>{let h=0;for(const c of s)h=(h*31+c.charCodeAt(0))%360;return h};
const name=e=>esc(String(e).split("@")[0]);
const ICON={phone:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="2" width="12" height="20" rx="3"/><path d="M11 18h2"/></svg>',
desktop:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
web:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>'};
const kind=d=>/^Web/.test(d)?"web":/Desktop/.test(d)?"desktop":"phone";
let first=true,lastTicker="",ME=null,CANDS=[];
function chart(u,days){const d=u.daily,bytes=u.daily_bytes||[],m=Math.max(1,...d),tot=d.reduce((a,b)=>a+b,0),totB=bytes.reduce((a,b)=>a+b,0);
return`<div class="ch"><div class="chhead"><span>Uploads per day · last ${d.length} days</span><span><b>${tot.toLocaleString()}</b> files · ${fmtB(totB)}</span></div><div class="bars">`+
d.map((v,i)=>`<span class="b${v?"":" zero"}${i===d.length-1?" today":""}" tabindex="0" data-day="${esc(days[i])}${i===d.length-1?" (today)":""}" data-n="${v}" data-b="${bytes[i]||0}"><i style="height:${v?Math.max(6,v/m*100):4}%"></i></span>`).join("")+
`</div><div class="chartlab"><span>${esc(days[0])}</span><span>today</span></div></div>`}
function dev(x){const fresh=x.last_seen&&Date.now()/1000-x.last_seen<600;return`<div class="dev${fresh?" fresh":""}">${ICON[kind(x.device)]}<span class="nm" title="${esc(x.device)}">${esc(x.device)}</span><span class="t">${ago(x.last_seen)}</span></div>`}
function share(inst,u){if(!ME||!ME.admin)return"";const avail=CANDS.filter(c=>!u.shared_with.includes(c.user));
const picker=avail.length?`<form class="shf" hidden><select name="u" aria-label="share with" required><option value="">choose a user…</option>${avail.map(c=>`<option value="${esc(c.user)}">${esc(c.name)}${c.name!==c.user?" ("+esc(c.user)+")":""}</option>`).join("")}</select><button>Add</button></form>`
:`<span class="shf hint" hidden>no more users to share with. Add one with authelia-user.sh … --groups app-ente-admin</span>`;
return`<div class="share" data-inst="${esc(inst)}" data-id="${u.id}">👥 Visible to: <span class="sh" title="admins see every account">admins</span>${u.shared_with.map(n=>`<span class="sh">${esc(nameOf(n))}<button data-act="rm" data-user="${esc(n)}" title="stop sharing with ${esc(n)}" aria-label="remove ${esc(n)}">✕</button></span>`).join("")}<button class="addsh" data-act="add">+ share</button>${picker}</div>`}
function userMenu(){const n=ME.name||ME.user,ini=esc((n[0]||"?").toUpperCase());
return`<button class="mebtn" id="mebtn" aria-haspopup="menu" aria-expanded="false"><span class="meav">${ini}</span><span class="nm">${esc(n)}</span><svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m6 9 6 6 6-6"/></svg></button>
<div class="menu" id="menu" role="menu" hidden><div class="mhead"><span class="meav">${ini}</span><div><b>${esc(n)}</b><span>${esc(ME.user)}</span><br><span class="role">${ME.admin?"Admin":"Viewer"}</span></div></div>
<a class="mitem out" role="menuitem" href="${LOGOUT}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3"/></svg>Log out</a></div>`}
function toggleMenu(open){const b=document.getElementById("mebtn"),m=document.getElementById("menu");if(!b)return;const o=open===undefined?m.hidden:open;m.hidden=!o;b.setAttribute("aria-expanded",String(o));if(o)m.querySelector(".mitem").focus()}
document.addEventListener("click",e=>{if(e.target.closest&&e.target.closest("#mebtn")){toggleMenu();return}if(!(e.target.closest&&e.target.closest("#menu")))toggleMenu(false)});
document.addEventListener("keydown",e=>{if(e.key==="Escape")toggleMenu(false)});
function nameOf(user){const c=CANDS.find(x=>x.user===user);return c&&c.name!==user?c.name+" ("+user+")":user}
function card(u,days,idx,inst){const pct=u.quota?Math.min(100,u.used/u.quota*100):0;const ini=(u.email[0]||"?").toUpperCase();const h=hue(u.email);
const sec=(u.two_factor?'<span class="tag2">2FA app</span>':"")+(u.email_mfa?'<span class="tag2">email code</span>':"")+(!u.two_factor&&!u.email_mfa?'<span class="tag2 warn">password only</span>':"");
const devs=u.devices,shown=devs.slice(0,3),rest=devs.slice(3);
return`<div class="card${u.uploading?" live":""}${first?" enter":""}" style="${first?`animation-delay:${idx*70}ms`:""}"><div class="head"><div class="av" style="background:linear-gradient(135deg,hsl(${h} 70% 55%),hsl(${(h+40)%360} 70% 42%))">${esc(ini)}</div>
<div class="who"><div class="email" title="${esc(u.email)}">${esc(u.email)}${u.own?'<span class="ownb">you</span>':""}</div><div class="meta">since ${day(u.created)} · id ${u.id}</div></div>
${u.uploading?`<span class="status on"><span class="dot"></span>uploading · ${u.recent} / 5 min</span>`:`<span class="status">seen ${ago(u.last_seen)}</span>`}</div>
<div class="store"><span><b>${fmtB(u.used)}</b> of ${fmtB(u.quota)}</span><span class="meta">${pct.toFixed(1)}%</span></div><div class="bar"><div class="${pct>90?"hot":""}" style="width:${pct}%"></div></div>
<div class="mini"><div><div class="n">${u.files.toLocaleString()}</div><div class="l">files</div></div><div><div class="n">${fmtB(u.bytes)}</div><div class="l" title="Combined size of the uploaded files (without thumbnails); the bar above shows the quota usage">size</div></div><div><div class="n">${u.albums}</div><div class="l">albums</div></div><div><div class="n">${u.trash}</div><div class="l">in trash</div></div></div>
${chart(u,days)}
<div class="sec">${sec}<span class="tag2 plain">last upload ${ago(u.last_upload)}</span><span class="tag2 plain">plan until ${day(u.expiry)}</span></div>
<div class="devs">${shown.map(dev).join("")||'<div class="meta">no devices</div>'}${rest.length?`<details><summary>+ ${rest.length} older session${rest.length>1?"s":""}</summary>${rest.map(dev).join("")}</details>`:""}</div>${share(inst,u)}</div>`}
function stat(k,v,s,img,cls){return`<div class="stat ${cls||""}"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${s||""}</div>${img?`<img src="${img}" alt="">`:""}</div>`}
function ticker(all){const items=all.map(u=>u.uploading?`<div class="item">🟢 <b>${name(u.email)}</b> is uploading <span class="m">${u.recent} files in the last 5 min</span></div>`:`<div class="item">📷 <b>${name(u.email)}</b> <span class="m">${u.files.toLocaleString()} files · ${fmtB(u.used)}</span></div>`);
const html=items.join("");if(html===lastTicker)return;lastTicker=html;document.getElementById("track").innerHTML=html+html}
const LOGOUT="https://auth.agathla.com/logout?rd="+encodeURIComponent("https://ente-admin.agathla.com/");
async function load(force){if(!force&&document.activeElement&&document.activeElement.closest&&document.activeElement.closest(".shf"))return;
try{const r=await fetch("api/data",{cache:"no-store",redirect:"manual"});
// Session expired: Authelia answers with a redirect to its login. Reload the page so the
// browser follows it to the login (and comes back here afterwards).
if(r.type==="opaqueredirect"||r.status===401||r.status===403||r.status===302){location.reload();return}
const d=await r.json();ME=d.me;CANDS=d.candidates||[];
const me=document.getElementById("me");if(me.hidden){me.hidden=false;me.innerHTML=userMenu()}
document.getElementById("sub").textContent=ME.admin?"Your self-hosted photo servers, at a glance. Read-only, refreshed every 30 seconds.":"Your Ente accounts at a glance, refreshed every 30 seconds.";const all=d.instances.flatMap(i=>i.users);const live=all.filter(u=>u.uploading);
const used=all.reduce((a,u)=>a+u.used,0),files=all.reduce((a,u)=>a+u.files,0);
document.getElementById("chips").innerHTML=`<span class="chip">👥 ${all.length} accounts</span><span class="chip">🗄️ ${d.instances.length} servers</span><span class="chip">${live.length?"🚀 "+live.length+" uploading":"😴 all quiet"}</span><span class="chip">⏱ ${new Date(d.generated*1000).toLocaleTimeString()}</span>`;
ticker(all);
document.getElementById("stats").innerHTML=stat("Accounts",all.length,`on ${d.instances.length} servers`,"media/feature-family-plan.webp")+stat("Storage used",fmtB(used),`${files.toLocaleString()} files`)+stat("Uploading now",live.length,live.length?live.reduce((a,u)=>a+u.recent,0)+" files in the last 5 min":"nobody right now","media/rocketship.webp",live.length?"go":"");
document.getElementById("root").innerHTML=!d.instances.length?`<div class="empty"><img src="media/floss-fund.png" alt=""><div><b>Nothing shared with you yet.</b><div class="meta">Ask an admin to share an account with your username (${esc(ME.user)}).</div></div></div>`:d.instances.map(i=>`<div class="inst"><h2>${esc(i.name)}</h2><span class="pill">${i.users.length} account${i.users.length===1?"":"s"} · ${fmtB(i.users.reduce((a,u)=>a+u.used,0))}</span><a href="${esc(i.url)}" target="_blank" rel="noopener">${esc(i.url.replace("https://",""))} ↗</a></div>`+(i.error?`<div class="card oops"><img src="media/floss-fund.png" alt=""><div><b>Can't reach this server right now.</b><div class="meta">${esc(i.error)}</div></div></div>`:`<div class="grid">${i.users.map((u,k)=>card(u,i.days,k,i.name)).join("")}</div>`)).join("");
first=false}
catch(e){document.getElementById("chips").innerHTML=`<span class="chip">⚠️ error loading data</span>`}}
async function grant(add,inst,id,user){const r=await fetch("api/grants",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({add,instance:inst,account_id:id,username:user})});
if(!r.ok)alert("Couldn't change sharing ("+r.status+")");await load(true)}
document.addEventListener("click",e=>{const btn=e.target.closest&&e.target.closest(".share button[data-act]");if(!btn)return;e.preventDefault();const row=btn.closest(".share");
if(btn.dataset.act==="add"){const f=row.querySelector(".shf");f.hidden=false;btn.hidden=true;const sel=f.querySelector("select");if(sel)sel.focus()}
else if(btn.dataset.act==="rm"&&confirm("Stop sharing this account with "+btn.dataset.user+"?"))grant(false,row.dataset.inst,+row.dataset.id,btn.dataset.user)});
document.addEventListener("submit",e=>{const f=e.target.closest&&e.target.closest(".shf");if(!f)return;e.preventDefault();const row=f.closest(".share");
const u=f.querySelector("select").value;if(u)grant(true,row.dataset.inst,+row.dataset.id,u)});
const tip=document.getElementById("tip");
function showTip(b){const n=+b.dataset.n,by=+b.dataset.b,r=b.getBoundingClientRect();
tip.innerHTML=`<b>${esc(b.dataset.day)}</b><br>${n?n.toLocaleString()+" file"+(n===1?"":"s")+" added or changed"+(by?" · "+fmtB(by):""):"no uploads"}`;
tip.style.left=(r.left+r.width/2)+"px";tip.style.top=r.top+"px";tip.classList.add("on");
document.querySelectorAll(".bars .b.sel").forEach(x=>x.classList.remove("sel"));b.classList.add("sel")}
function hideTip(){tip.classList.remove("on");document.querySelectorAll(".bars .b.sel").forEach(x=>x.classList.remove("sel"))}
document.addEventListener("mouseover",e=>{const b=e.target.closest&&e.target.closest(".bars .b");if(b)showTip(b)});
document.addEventListener("mouseout",e=>{if(e.target.closest&&e.target.closest(".bars .b")&&!(e.relatedTarget&&e.relatedTarget.closest&&e.relatedTarget.closest(".bars .b")))hideTip()});
document.addEventListener("focusin",e=>{const b=e.target.closest&&e.target.closest(".bars .b");if(b)showTip(b)});
document.addEventListener("focusout",hideTip);
document.addEventListener("click",e=>{const b=e.target.closest&&e.target.closest(".bars .b");if(b)showTip(b);else hideTip()});
window.addEventListener("scroll",hideTip,{passive:true});
load();setInterval(load,30000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        cache = "no-store"
        if path in ("/", "/index.html"):
            body, ctype = PAGE.encode(), "text/html; charset=utf-8"
        elif path == "/api/data":
            me = viewer(self.headers)
            if not me["user"]:  # only reachable through Authelia; no user means misconfiguration
                self.send_error(403)
                return
            body, ctype = json.dumps(for_viewer(snapshot(), me)).encode(), "application/json"
        elif path == "/healthz":
            body, ctype = b"ok", "text/plain"
        elif path.startswith("/media/") and os.path.basename(path) in MEDIA:
            name = os.path.basename(path)  # only names that exist in the media folder
            with open(os.path.join(MEDIA_DIR, name), "rb") as f:
                body = f.read()
            ctype, cache = MEDIA[name], "public, max-age=86400"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        """Admins share/unshare an account with a username: {"add": bool, "username", "instance", "account_id"}."""
        me = viewer(self.headers)
        # Same-origin JSON requests only (blocks forged cross-site posts), and admins only
        if (self.path.split("?")[0] != "/api/grants" or not me["admin"]
                or self.headers.get("Origin") != PUBLIC_ORIGIN
                or not (self.headers.get("Content-Type") or "").startswith("application/json")):
            self.send_error(403)
            return
        try:
            req = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096)))
            username = str(req["username"]).strip().lower()
            instance = str(req["instance"])
            account_id = int(req["account_id"])
            if not USERNAME_RE.match(username) or instance not in {i["name"] for i in INSTANCES}:
                raise ValueError("invalid username or instance")
        except Exception:
            self.send_error(400)
            return
        change_grant(bool(req.get("add")), username, instance, account_id, me["user"])
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # keep logs quiet: no emails or paths in the log
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
