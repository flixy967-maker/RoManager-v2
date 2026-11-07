"""
RoManager - Roblox multi-account manager and multi-instance launcher.
Python 3.11+, Windows 10/11 x64.  Dependencies: customtkinter, psutil, Pillow.
 
Status: first full draft, written without a Windows machine to test on.
Expect to paste back errors from the first runs.
 
Not implemented (deliberately, no fake buttons): tray icon, language packs,
auto-updater, FPS cap (Roblox no longer supports FFlag overrides), whole-file
database encryption (secrets are DPAPI-encrypted per field), embedded login
window, adopting Roblox clients that were started before RoManager.
"""
import collections, ctypes, hashlib, hmac, io, json, math, os, queue, random
import re, secrets, sqlite3, sys, threading, time, urllib.error
import urllib.parse, urllib.request
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from tkinter import colorchooser, messagebox, simpledialog
 
if sys.platform != "win32":
    print("RoManager only runs on Windows 10/11.")
    sys.exit(1)
 
import psutil
import customtkinter as ctk
 
try:
    from PIL import Image
except Exception:  # avatars are optional
    Image = None
 
APP_NAME = "RoManager"
APPDIR = Path(os.environ.get("APPDATA", ".")) / APP_NAME
PROC_NAME = "RobloxPlayerBeta.exe"
NCPU = psutil.cpu_count() or 1
 
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
crypt32 = ctypes.windll.crypt32
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.CreateMutexW.restype = ctypes.c_void_p
kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
 
# ----------------------------------------------------------------- DPAPI ---
class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
 
 
def _to_blob(data: bytes):
    buf = ctypes.create_string_buffer(data, len(data))
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf
 
 
def _from_blob(blob: DATA_BLOB) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(blob.pbData, ctypes.c_void_p))
 
 
def dpapi_protect(data: bytes) -> bytes:
    inb, _keep = _to_blob(data)
    out = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(inb), APP_NAME, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    return _from_blob(out)
 
 
def dpapi_unprotect(data: bytes) -> bytes:
    inb, _keep = _to_blob(data)
    out = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    return _from_blob(out)
 
 
def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return salt.hex() + "$" + h.hex()
 
 
def verify_pw(pw: str, stored: str) -> bool:
    try:
        s, h = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(s), 200_000)
        return hmac.compare_digest(calc.hex(), h)
    except Exception:
        return False
 
 
# -------------------------------------------------------------- database ---
DEFAULTS = {
    "theme": "dark", "start_min": "0", "delay": "8", "default_dest": "",
    "auto": "0", "max_attempts": "3", "restart_delay": "15",
    "preset": "balanced", "interval": "2", "monitor": "0",
    "c_prio": "Normal", "c_w": "0", "c_h": "0", "c_automin": "0",
    "multi": "1", "webhook": "", "wh_on": "0",
    "n_crash": "1", "n_hung": "1", "n_restart": "1", "n_launch": "1",
    "lock_hash": "",
}
 
MIGRATIONS = [
    """BEGIN;
    CREATE TABLE groups(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
    CREATE TABLE accounts(
        id INTEGER PRIMARY KEY, user_id INTEGER, username TEXT NOT NULL,
        alias TEXT, color TEXT, label TEXT,
        group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
        is_main INTEGER DEFAULT 0, cookie_enc BLOB NOT NULL,
        status TEXT DEFAULT 'Unknown', robux INTEGER, last_used REAL,
        created REAL);
    CREATE TABLE clients(pid INTEGER PRIMARY KEY, account_id INTEGER, dest TEXT, started REAL);
    CREATE TABLE favourites(id INTEGER PRIMARY KEY, place_id INTEGER UNIQUE, name TEXT);
    CREATE TABLE launch_history(id INTEGER PRIMARY KEY, account_id INTEGER, dest TEXT,
        ts REAL, ok INTEGER, error TEXT);
    CREATE TABLE layouts(name TEXT PRIMARY KEY, data TEXT);
    CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE recovery_history(id INTEGER PRIMARY KEY, account_id INTEGER, ts REAL,
        attempt INTEGER, result TEXT);
    COMMIT;""",
]
 
 
class DB:
    def __init__(self):
        APPDIR.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.c = sqlite3.connect(APPDIR / "romanager.db", check_same_thread=False)
        self.c.row_factory = sqlite3.Row
        self.c.execute("PRAGMA journal_mode=WAL")
        self.c.execute("PRAGMA foreign_keys=ON")
        ver = self.c.execute("PRAGMA user_version").fetchone()[0]
        for i, sql in enumerate(MIGRATIONS[ver:], start=ver + 1):
            with self.lock:
                self.c.executescript(sql)
                self.c.execute(f"PRAGMA user_version={i}")
                self.c.commit()
 
    def q(self, sql, args=()):
        with self.lock:
            cur = self.c.execute(sql, args)
            self.c.commit()
            return cur
 
    def all(self, sql, args=()):
        with self.lock:
            return self.c.execute(sql, args).fetchall()
 
    def one(self, sql, args=()):
        with self.lock:
            return self.c.execute(sql, args).fetchone()
 
    def get(self, k):
        r = self.one("SELECT value FROM settings WHERE key=?", (k,))
        return r[0] if r else DEFAULTS.get(k, "")
 
    def set(self, k, v):
        self.q("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
               (k, str(v)))
 
    def flag(self, k):
        return self.get(k) == "1"
 
    def num(self, k, lo, hi):
        try:
            return max(lo, min(hi, int(float(self.get(k)))))
        except ValueError:
            return int(DEFAULTS[k])
 
 
# ------------------------------------------------------------ roblox web ---
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) RoManager/1.0"
 
 
class AuthExpired(Exception):
    pass
 
 
def http(method, url, headers=None, body=None, timeout=15):
    h = {"User-Agent": UA}
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
 
 
def ck(cookie):
    return {"Cookie": f".ROBLOSECURITY={cookie}"}
 
 
def whoami(cookie):
    s, _, b = http("GET", "https://users.roblox.com/v1/users/authenticated", ck(cookie))
    if s == 401:
        raise AuthExpired("Session is invalid or expired.")
    if s != 200:
        raise RuntimeError(f"Roblox returned HTTP {s} while verifying the session.")
    return json.loads(b)
 
 
def get_robux(cookie, uid):
    s, _, b = http("GET", f"https://economy.roblox.com/v1/users/{uid}/currency", ck(cookie))
    return json.loads(b).get("robux") if s == 200 else None
 
 
def get_avatar(uid):
    s, _, b = http("GET", "https://thumbnails.roblox.com/v1/users/avatar-headshot"
                   f"?userIds={uid}&size=48x48&format=Png")
    if s != 200:
        return None
    url = json.loads(b)["data"][0].get("imageUrl")
    if not url:
        return None
    s, _, img = http("GET", url)
    return img if s == 200 else None
 
 
def auth_ticket(cookie):
    url = "https://auth.roblox.com/v1/authentication-ticket"
    h = {**ck(cookie), "Referer": "https://www.roblox.com/", "Origin": "https://www.roblox.com",
         "Content-Type": "application/json"}
    s, hd, _ = http("POST", url, h, b"{}")
    if s == 403 and "x-csrf-token" in hd:
        h["X-CSRF-TOKEN"] = hd["x-csrf-token"]
        s, hd, _ = http("POST", url, h, b"{}")
    if s == 401:
        raise AuthExpired("Authentication expired. Re-add this account.")
    if s == 200 and "rbx-authentication-ticket" in hd:
        return hd["rbx-authentication-ticket"]
    raise RuntimeError(f"Could not get a launch ticket (HTTP {s}).")
 
 
def parse_dest(text):
    t = (text or "").strip()
    if not t:
        raise ValueError("Enter a place ID or a Roblox experience link.")
    if re.fullmatch(r"\d{1,19}", t):
        return {"place_id": int(t)}
    u = urllib.parse.urlparse(t)
    host = (u.hostname or "").lower()
    if u.scheme in ("http", "https") and (host == "roblox.com" or host.endswith(".roblox.com")):
        m = re.search(r"/games/(\d{1,19})", u.path)
        if m:
            d = {"place_id": int(m.group(1))}
            q = urllib.parse.parse_qs(u.query)
            code = q.get("privateServerLinkCode", [""])[0]
            if code:
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", code):
                    raise ValueError("Private server link code looks invalid.")
                d["link_code"] = code
            job = q.get("gameInstanceId", [""])[0]
            if job:
                if not re.fullmatch(r"[0-9a-fA-F-]{36}", job):
                    raise ValueError("Server (job) id looks invalid.")
                d["job_id"] = job
            return d
        raise ValueError("Link must contain /games/<place id>. Share links (roblox.com/share) are not supported.")
    raise ValueError("Not a valid place ID or roblox.com experience link.")
 
 
def dest_label(d):
    return str(d["place_id"]) + (" (private)" if d.get("link_code") else "") + (" (server)" if d.get("job_id") else "")
 
 
def build_uri(ticket, d):
    tid = str(random.randint(10**10, 10**11 - 1))
    p = f"request=RequestGame&browserTrackerId={tid}&placeId={d['place_id']}&isPlayTogetherGame=false"
    if d.get("job_id"):
        p = f"request=RequestGameJob&browserTrackerId={tid}&placeId={d['place_id']}&gameId={d['job_id']}&isPlayTogetherGame=false"
    elif d.get("link_code"):
        p += f"&linkCode={d['link_code']}"
    pl = urllib.parse.quote("https://assetgame.roblox.com/game/PlaceLauncher.ashx?" + p, safe="")
    return (f"roblox-player:1+launchmode:play+gameinfo:{ticket}+launchtime:{int(time.time() * 1000)}"
            f"+placelauncherurl:{pl}+browsertrackerid:{tid}+robloxLocale:en_us+gameLocale:en_us+channel:+LaunchExp:InApp")
 
 
def roblox_installed():
    roots = [Path(os.environ.get("LOCALAPPDATA", "")) / "Roblox" / "Versions",
             Path(os.environ.get("ProgramFiles(x86)", "")) / "Roblox" / "Versions"]
    return any(r.exists() and any(r.glob("*/RobloxPlayerBeta.exe")) for r in roots)
 
 
def roblox_pids():
    return {p.pid for p in psutil.process_iter(["name"]) if p.info["name"] == PROC_NAME}
 
 
WEBHOOK_RE = re.compile(r"^https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+$")
 
 
def discord_post(url, text):
    body = json.dumps({"content": text[:1900], "username": APP_NAME}).encode()
    s, _, _ = http("POST", url, {"Content-Type": "application/json"}, body, timeout=10)
    return s in (200, 204)
 
 
# --------------------------------------------------------------- windows ---
EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
MonEnumProc = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.c_void_p, ctypes.c_void_p,
                                 ctypes.POINTER(wintypes.RECT), wintypes.LPARAM)
 
 
class MONITORINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT),
                ("rcWork", wintypes.RECT), ("dwFlags", wintypes.DWORD)]
 
 
def find_windows(pids):
    out = {}
 
    def cb(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value in pids:
                r = wintypes.RECT()
                user32.GetWindowRect(hwnd, ctypes.byref(r))
                area = (r.right - r.left) * (r.bottom - r.top)
                if area > out.get(pid.value, (0, 0))[1]:
                    out[pid.value] = (hwnd, area)
        return True
 
    user32.EnumWindows(EnumWindowsProc(cb), 0)
    return {p: v[0] for p, v in out.items()}
 
 
def monitors():
    res = []
 
    def cb(hm, hdc, rc, lp):
        mi = MONITORINFO()
        mi.cbSize = ctypes.sizeof(MONITORINFO)
        if user32.GetMonitorInfoW(hm, ctypes.byref(mi)):
            r = mi.rcWork
            res.append((r.left, r.top, r.right - r.left, r.bottom - r.top, bool(mi.dwFlags & 1)))
        return True
 
    user32.EnumDisplayMonitors(None, None, MonEnumProc(cb), 0)
    res.sort(key=lambda m: not m[4])
    return [m[:4] for m in res] or [(0, 0, user32.GetSystemMetrics(0), user32.GetSystemMetrics(1))]
 
 
def win_show(hwnd, cmd):  # 6 minimize, 3 maximize, 9 restore
    user32.ShowWindow(hwnd, cmd)
 
 
def win_focus(hwnd):
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, 9)
    user32.SetForegroundWindow(hwnd)
 
 
def win_place(hwnd, x, y, w, h):
    if user32.IsIconic(hwnd) or user32.IsZoomed(hwnd):
        user32.ShowWindow(hwnd, 9)
    user32.SetWindowPos(hwnd, 0, int(x), int(y), int(w), int(h), 0x0004 | 0x0010)  # NOZORDER|NOACTIVATE
 
 
def win_rect(hwnd):
    r = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    return [r.left, r.top, r.right - r.left, r.bottom - r.top]
 
 
def win_state(hwnd):
    if not hwnd:
        return "No window"
    if user32.IsHungAppWindow(hwnd):
        return "Not responding"
    if user32.IsIconic(hwnd):
        return "Minimized"
    if user32.IsZoomed(hwnd):
        return "Maximized"
    return "Normal"
 
 
# ------------------------------------------------------------------ core ---
def fmt_dur(s):
    s = int(max(0, s))
    return f"{s // 3600:d}:{s % 3600 // 60:02d}:{s % 60:02d}"
 
 
def fmt_mb(b):
    return f"{b / 1048576:,.0f} MB"
 
 
class Core:
    def __init__(self):
        self.db = DB()
        self.clients = {}
        self.lock = threading.RLock()
        self.logs = []
        self.hist = collections.deque(maxlen=3700)
        self.started = time.time()
        self.attempts = {}
        self.failed = 0
        self.mutex = None
        self.last_net = None
        self.qs = {"running": False, "total": 0, "done": 0, "failed": 0}
        self.pause_ev = threading.Event()
        self.pause_ev.set()
        self.cancel_ev = threading.Event()
        self.stop = False
 
    # -- infra
    def log(self, msg):
        self.logs.append(f"[{datetime.now():%H:%M:%S}] {msg}")
 
    def start(self):
        psutil.cpu_percent(None)
        threading.Thread(target=self.sample_loop, daemon=True).start()
        if self.db.flag("multi"):
            self.log(self.set_multi(True))
 
    def shutdown(self):
        self.stop = True
        self.cancel_ev.set()
 
    def notify(self, kind, text):
        if not self.db.flag("wh_on") or not self.db.flag("n_" + kind):
            return
        enc = self.db.get("webhook")
        if not enc:
            return
 
        def send():
            try:
                url = dpapi_unprotect(bytes.fromhex(enc)).decode()
                if not discord_post(url, text):
                    self.log("Discord webhook rejected the message.")
            except Exception as e:
                self.log(f"Discord notification failed: {e}")
 
        threading.Thread(target=send, daemon=True).start()
 
    # -- multi-instance (holds Roblox's documented-by-observation named mutex in OUR process)
    def set_multi(self, on):
        if not on:
            if self.mutex:
                kernel32.CloseHandle(ctypes.c_void_p(self.mutex))
                self.mutex = None
            return "Multi-instance off."
        if self.mutex:
            return "Multi-instance already on."
        h = kernel32.CreateMutexW(None, True, "ROBLOX_singletonMutex")
        err = ctypes.get_last_error() or kernel32.GetLastError()
        if not h:
            return "Could not create the instance mutex."
        if err == 183:  # already exists -> someone else (Roblox) owns it
            kernel32.CloseHandle(ctypes.c_void_p(h))
            return "Roblox is already running and owns the mutex. Close all Roblox windows, then enable multi-instance."
        self.mutex = h
        return "Multi-instance on (mutex held). Depends on your Roblox version; verify with 2 accounts."
 
    # -- launching
    def launch_one(self, aid, dest):
        if not roblox_installed():
            raise RuntimeError("Roblox Player is not installed for this Windows user.")
        acc = self.db.one("SELECT * FROM accounts WHERE id=?", (aid,))
        if not acc:
            raise RuntimeError("Account no longer exists.")
        name = acc["alias"] or acc["username"]
        try:
            cookie = dpapi_unprotect(acc["cookie_enc"]).decode()
            ticket = auth_ticket(cookie)
        except AuthExpired:
            self.db.q("UPDATE accounts SET status='Expired' WHERE id=?", (aid,))
            raise
        finally:
            cookie = None
        before = roblox_pids()
        os.startfile(build_uri(ticket, dest))
        pid, end = None, time.time() + 60
        while pid is None and time.time() < end and not self.stop:
            time.sleep(1)
            with self.lock:
                tracked = set(self.clients)
            new = roblox_pids() - before - tracked
            if new:
                pid = min(new)
        if pid is None:
            raise RuntimeError("Roblox did not start within 60s (updating? multi-instance blocked?).")
        c = {"pid": pid, "account_id": aid, "name": name, "dest": dest, "start": time.time(),
             "proc": psutil.Process(pid), "cpu": 0.0, "rss": 0, "hwnd": None, "hung": 0, "expected": False}
        c["proc"].cpu_percent(None)
        with self.lock:
            self.clients[pid] = c
        self.db.q("INSERT OR REPLACE INTO clients(pid,account_id,dest,started) VALUES(?,?,?,?)",
                  (pid, aid, dest_label(dest), c["start"]))
        self.db.q("UPDATE accounts SET last_used=?, status='Valid' WHERE id=?", (time.time(), aid))
        threading.Thread(target=self.apply_when_ready, args=(pid,), daemon=True).start()
        return pid
 
    def start_queue(self, ids, dest, delay):
        if self.qs["running"]:
            raise RuntimeError("A launch queue is already running.")
        self.cancel_ev.clear()
        self.pause_ev.set()
        self.qs.update(running=True, total=len(ids), done=0, failed=0)
        threading.Thread(target=self._queue, args=(list(ids), dest, delay), daemon=True).start()
 
    def _queue(self, ids, dest, delay):
        for i, aid in enumerate(ids):
            self.pause_ev.wait()
            if self.cancel_ev.is_set():
                self.log("Launch queue cancelled.")
                break
            row = self.db.one("SELECT username, alias FROM accounts WHERE id=?", (aid,))
            name = (row["alias"] or row["username"]) if row else str(aid)
            self.log(f"Launching {name} -> {dest_label(dest)}")
            try:
                pid = self.launch_one(aid, dest)
                self.db.q("INSERT INTO launch_history(account_id,dest,ts,ok) VALUES(?,?,?,1)",
                          (aid, dest_label(dest), time.time()))
                self.log(f"{name}: started (PID {pid})")
            except Exception as e:
                self.qs["failed"] += 1
                self.failed += 1
                self.db.q("INSERT INTO launch_history(account_id,dest,ts,ok,error) VALUES(?,?,?,0,?)",
                          (aid, dest_label(dest), time.time(), str(e)))
                self.log(f"{name}: FAILED - {e}")
            self.qs["done"] = i + 1
            if i < len(ids) - 1:
                t_end = time.time() + delay
                while time.time() < t_end and not self.cancel_ev.is_set():
                    self.pause_ev.wait()
                    time.sleep(0.25)
        self.qs["running"] = False
        ok = self.qs["done"] - self.qs["failed"]
        self.log(f"Queue finished: {ok} ok, {self.qs['failed']} failed.")
        self.notify("launch", f"Launch finished: {ok} started, {self.qs['failed']} failed.")
 
    # -- client control
    def snapshot(self):
        with self.lock:
            return list(self.clients.values())
 
    def close_client(self, pid, expected=True):
        with self.lock:
            c = self.clients.get(pid)
        if c:
            c["expected"] = expected
            try:
                c["proc"].terminate()
            except psutil.Error as e:
                self.log(f"Close failed for PID {pid}: {e}")
 
    def restart_client(self, pid):
        with self.lock:
            c = self.clients.get(pid)
        if not c:
            return
        aid, dest = c["account_id"], c["dest"]
        self.close_client(pid)
 
        def go():
            time.sleep(2)
            try:
                self.launch_one(aid, dest)
                self.log(f"{c['name']}: restarted")
            except Exception as e:
                self.log(f"{c['name']}: restart failed - {e}")
 
        threading.Thread(target=go, daemon=True).start()
 
    def close_all(self):
        for c in self.snapshot():
            self.close_client(c["pid"])
 
    def window_cmd(self, pid, cmd):
        with self.lock:
            c = self.clients.get(pid)
        if not c or not c["hwnd"]:
            self.log("Window not found for that client.")
            return
        {"min": lambda h: win_show(h, 6), "max": lambda h: win_show(h, 3),
         "restore": lambda h: win_show(h, 9), "focus": win_focus}[cmd](c["hwnd"])
 
    def window_all(self, cmd):
        for c in self.snapshot():
            self.window_cmd(c["pid"], cmd)
 
    def resize(self, pid, w, h):
        with self.lock:
            c = self.clients.get(pid)
        if c and c["hwnd"]:
            x, y, _, _ = win_rect(c["hwnd"])
            win_place(c["hwnd"], x, y, w, h)
 
    def arrange(self, mode):
        cl = [c for c in self.snapshot() if c["hwnd"]]
        if not cl:
            self.log("No client windows to arrange.")
            return
        mons = monitors()
        x, y, w, h = mons[min(self.db.num("monitor", 0, 16), len(mons) - 1)]
        n = len(cl)
        if mode == "h":
            cols, rows = n, 1
        elif mode == "v":
            cols, rows = 1, n
        else:
            cols = math.ceil(math.sqrt(n))
            rows = math.ceil(n / cols)
        cw, ch = w // cols, h // rows
        for i, c in enumerate(cl):
            r, k = divmod(i, cols)
            win_place(c["hwnd"], x + k * cw, y + r * ch, cw, ch)
 
    def save_layout(self, name):
        data = {str(c["account_id"]): win_rect(c["hwnd"]) for c in self.snapshot() if c["hwnd"]}
        self.db.q("INSERT INTO layouts(name,data) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET data=excluded.data",
                  (name, json.dumps(data)))
 
    def restore_layout(self, name):
        row = self.db.one("SELECT data FROM layouts WHERE name=?", (name,))
        if not row:
            raise ValueError(f"No layout named '{name}'.")
        data = json.loads(row[0])
        mons = monitors()
        minx = min(m[0] for m in mons)
        maxx = max(m[0] + m[2] for m in mons)
        miny = min(m[1] for m in mons)
        maxy = max(m[1] + m[3] for m in mons)
        for c in self.snapshot():
            r = data.get(str(c["account_id"]))
            if r and c["hwnd"]:
                x, y, w, h = r  # clamp so a layout saved on another monitor setup stays on-screen
                x = max(minx, min(x, maxx - 100))
                y = max(miny, min(y, maxy - 100))
                win_place(c["hwnd"], x, y, w, h)
 
    # -- performance
    def profile(self):
        p = self.db.get("preset")
        if p == "low":
            return {"prio": psutil.BELOW_NORMAL_PRIORITY_CLASS, "size": (640, 360), "automin": False,
                    "interval": max(5, self.db.num("interval", 1, 30))}
        if p == "custom":
            prio = {"Normal": psutil.NORMAL_PRIORITY_CLASS, "Below normal": psutil.BELOW_NORMAL_PRIORITY_CLASS,
                    "Idle": psutil.IDLE_PRIORITY_CLASS}.get(self.db.get("c_prio"), psutil.NORMAL_PRIORITY_CLASS)
            w, h = self.db.num("c_w", 0, 8000), self.db.num("c_h", 0, 8000)
            return {"prio": prio, "size": (w, h) if w >= 320 and h >= 200 else None,
                    "automin": self.db.flag("c_automin"), "interval": self.db.num("interval", 1, 30)}
        return {"prio": psutil.NORMAL_PRIORITY_CLASS, "size": None, "automin": False,
                "interval": self.db.num("interval", 1, 30)}
 
    def apply_perf(self, c):
        pr = self.profile()
        try:
            c["proc"].nice(pr["prio"])
        except psutil.Error as e:
            self.log(f"Could not set priority for PID {c['pid']}: {e}")
        if pr["size"] and c["hwnd"]:
            x, y, _, _ = win_rect(c["hwnd"])
            win_place(c["hwnd"], x, y, *pr["size"])
 
    def apply_when_ready(self, pid):
        for _ in range(40):
            with self.lock:
                c = self.clients.get(pid)
            if not c:
                return
            w = find_windows({pid})
            if pid in w:
                c["hwnd"] = w[pid]
                break
            time.sleep(1)
        if c:
            self.apply_perf(c)
 
    def apply_all(self):
        for c in self.snapshot():
            self.apply_perf(c)
 
    # -- monitoring + recovery
    def sample_loop(self):
        while not self.stop:
            time.sleep(self.profile()["interval"])
            try:
                self.sample()
            except Exception as e:
                self.log(f"Monitor error: {e}")
 
    def sample(self):
        vm = psutil.virtual_memory()
        net = psutil.net_io_counters()
        now = time.time()
        up = down = 0.0
        if self.last_net:
            dt = max(0.001, now - self.last_net[0])
            up, down = (net.bytes_sent - self.last_net[1]) / dt, (net.bytes_recv - self.last_net[2]) / dt
        self.last_net = (now, net.bytes_sent, net.bytes_recv)
        cl = self.snapshot()
        wins = find_windows({c["pid"] for c in cl}) if cl else {}
        per, rb_cpu, rb_ram = {}, 0.0, 0
        for c in cl:
            p = c["proc"]
            try:
                if not p.is_running() or p.status() == psutil.STATUS_ZOMBIE:
                    raise psutil.NoSuchProcess(c["pid"])
                c["cpu"] = p.cpu_percent(None) / NCPU
                c["rss"] = p.memory_info().rss
                c["hwnd"] = wins.get(c["pid"], c["hwnd"])
                per[c["pid"]] = (c["cpu"], c["rss"])
                rb_cpu += c["cpu"]
                rb_ram += c["rss"]
                self._check_hung(c)
            except psutil.NoSuchProcess:
                self.on_exit(c["pid"])
        self.hist.append({"t": now, "cpu": psutil.cpu_percent(None), "ram_pct": vm.percent,
                          "ram_used": vm.used, "ram_avail": vm.available, "total": vm.total,
                          "rb_cpu": rb_cpu, "rb_ram": rb_ram, "up": up, "down": down, "per": per,
                          "count": len(per)})
        if self.profile()["automin"] and cl:
            fg = user32.GetForegroundWindow()
            for c in cl:
                if c["hwnd"] and c["hwnd"] != fg and not user32.IsIconic(c["hwnd"]):
                    win_show(c["hwnd"], 6)
 
    def _check_hung(self, c):
        if c["hwnd"] and user32.IsHungAppWindow(c["hwnd"]):
            c["hung"] += 1
        else:
            c["hung"] = 0
            c.pop("hung_notified", None)
        if c["hung"] >= 3 and not c.get("hung_notified"):
            c["hung_notified"] = True
            self.log(f"{c['name']}: client is not responding")
            self.notify("hung", f"{c['name']}: Roblox client (PID {c['pid']}) is not responding.")
            if self.db.flag("auto"):
                self.log(f"{c['name']}: terminating unresponsive client for recovery")
                self.close_client(c["pid"], expected=False)
 
    def on_exit(self, pid):
        with self.lock:
            c = self.clients.pop(pid, None)
        self.db.q("DELETE FROM clients WHERE pid=?", (pid,))
        if not c:
            return
        if c["expected"]:
            self.log(f"{c['name']}: client closed")
            return
        self.failed += 1
        self.log(f"{c['name']}: client exited unexpectedly (PID {pid})")
        self.notify("crash", f"{c['name']}: Roblox client (PID {pid}) exited unexpectedly.")
        if not self.db.flag("auto"):
            return
        aid = c["account_id"]
        if time.time() - c["start"] > 600:
            self.attempts[aid] = 0
        n = self.attempts.get(aid, 0)
        threading.Thread(target=self._recover, args=(aid, c["name"], c["dest"], n), daemon=True).start()
 
    def _recover(self, aid, name, dest, n):
        mx = self.db.num("max_attempts", 1, 20)
        while n < mx and not self.stop:
            n += 1
            self.attempts[aid] = n
            time.sleep(self.db.num("restart_delay", 1, 3600))
            try:
                self.launch_one(aid, dest)
                self.db.q("INSERT INTO recovery_history(account_id,ts,attempt,result) VALUES(?,?,?,?)",
                          (aid, time.time(), n, "restarted"))
                self.log(f"{name}: recovered (attempt {n}/{mx})")
                self.notify("restart", f"{name}: client restarted (attempt {n}/{mx}).")
                return
            except Exception as e:
                self.db.q("INSERT INTO recovery_history(account_id,ts,attempt,result) VALUES(?,?,?,?)",
                          (aid, time.time(), n, f"failed: {e}"))
                self.log(f"{name}: restart attempt {n}/{mx} failed - {e}")
        self.log(f"{name}: giving up after {mx} attempts")
        self.notify("restart", f"{name}: automatic restart gave up after {mx} attempts.")
 
 
# -------------------------------------------------------------------- UI ---
BG = ("#f3f4f6", "#0f1115")
PANEL = ("#ffffff", "#171a21")
BORDER = ("#d5d9e0", "#262b36")
ACCENT = "#5b8cff"
DANGER = "#e5484d"
SOFT = ("#e5e7eb", "#262b36")
MUTED = ("#6b7280", "#8b93a7")
 
 
def panel(parent, **kw):
    return ctk.CTkFrame(parent, fg_color=PANEL, border_color=BORDER, border_width=1, corner_radius=12, **kw)
 
 
def button(parent, text, cmd, w=96, kind="soft"):
    col = {"soft": SOFT, "accent": ACCENT, "danger": DANGER}[kind]
    tc = "#ffffff" if kind != "soft" else ("#111827", "#e5e7eb")
    return ctk.CTkButton(parent, text=text, command=cmd, width=w, height=30, corner_radius=8,
                         fg_color=col, hover_color=("#d1d5db", "#323847") if kind == "soft" else None, text_color=tc)
 
 
def ask_secret(parent, title, prompt):
    res = {"v": None}
    top = ctk.CTkToplevel(parent)
    top.title(title)
    top.geometry("340x170")
    ctk.CTkLabel(top, text=prompt).pack(pady=(18, 6))
    e = ctk.CTkEntry(top, show="•", width=260)
    e.pack()
 
    def ok(_=None):
        res["v"] = e.get()
        top.destroy()
 
    e.bind("<Return>", ok)
    button(top, "OK", ok, kind="accent").pack(pady=14)
    top.after(150, lambda: (top.grab_set(), e.focus_set()))
    parent.wait_window(top)
    return res["v"]
 
 
class Page(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app, self.core = app, app.core
        self.grid(row=0, column=0, sticky="nsew")
 
    def refresh(self):
        pass
 
 
class HomePage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.cards = {}
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x")
        self.stat = {}
        for key, title in [("clients", "Roblox clients"), ("ram", "Total RAM"), ("cpu", "Total CPU"),
                           ("running", "Running accounts"), ("failed", "Failed clients")]:
            p = panel(top)
            p.pack(side="left", expand=True, fill="x", padx=4)
            ctk.CTkLabel(p, text=title, text_color=MUTED, font=ctk.CTkFont(size=12)).pack(anchor="w", padx=14, pady=(10, 0))
            self.stat[key] = ctk.CTkLabel(p, text="-", font=ctk.CTkFont(size=22, weight="bold"))
            self.stat[key].pack(anchor="w", padx=14, pady=(0, 10))
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x", pady=10)
        for t, f, k in [("Launch selected", lambda: app.show("Play"), "accent"),
                        ("Close all", self.close_all, "danger"),
                        ("Minimize all", lambda: self.core.window_all("min"), "soft"),
                        ("Restore all", lambda: self.core.window_all("restore"), "soft"),
                        ("Tile horizontal", lambda: self.core.arrange("h"), "soft"),
                        ("Tile vertical", lambda: self.core.arrange("v"), "soft"),
                        ("Auto arrange", lambda: self.core.arrange("grid"), "soft"),
                        ("Save layout", self.save_layout, "soft"),
                        ("Restore layout", self.restore_layout, "soft"),
                        ("Refresh", lambda: app.bg(self.core.sample, lambda r, e: self.refresh()), "soft")]:
            button(bar, t, f, w=104, kind=k).pack(side="left", padx=3)
        self.list = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.list.pack(fill="both", expand=True)
        self.empty = ctk.CTkLabel(self.list, text="No Roblox clients running. Select accounts and use Play to launch.",
                                  text_color=MUTED)
 
    def close_all(self):
        if self.core.snapshot() and messagebox.askyesno(APP_NAME, "Close all Roblox clients?"):
            self.core.close_all()
 
    def save_layout(self):
        n = simpledialog.askstring(APP_NAME, "Layout name:", parent=self.app)
        if n and n.strip():
            self.core.save_layout(n.strip())
            self.core.log(f"Layout '{n.strip()}' saved.")
 
    def restore_layout(self):
        names = [r[0] for r in self.core.db.all("SELECT name FROM layouts ORDER BY name")]
        if not names:
            messagebox.showinfo(APP_NAME, "No saved layouts yet.")
            return
        n = simpledialog.askstring(APP_NAME, "Layout to restore:\n" + ", ".join(names), parent=self.app)
        if n:
            try:
                self.core.restore_layout(n.strip())
            except ValueError as e:
                messagebox.showerror(APP_NAME, str(e))
 
    def make_card(self, c):
        f = panel(self.list)
        f.pack(fill="x", pady=5, padx=2)
        head = ctk.CTkFrame(f, fg_color="transparent")
        head.pack(fill="x", padx=14, pady=(10, 0))
        img = self.app.avatar(c["account_id"])
        av = ctk.CTkLabel(head, text="", image=img, width=40) if img else ctk.CTkLabel(head, text="●", width=40, text_color=ACCENT)
        av.pack(side="left")
        ctk.CTkLabel(head, text=c["name"], font=ctk.CTkFont(size=15, weight="bold")).pack(side="left", padx=8)
        lab = {}
        for k in ("info", "res", "win"):
            lab[k] = ctk.CTkLabel(f, text="", text_color=MUTED, anchor="w")
            lab[k].pack(fill="x", padx=14)
        row = ctk.CTkFrame(f, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=10)
        pid = c["pid"]
        for t, cmd, k in [("Focus", lambda: self.core.window_cmd(pid, "focus"), "soft"),
                          ("Minimize", lambda: self.core.window_cmd(pid, "min"), "soft"),
                          ("Maximize", lambda: self.core.window_cmd(pid, "max"), "soft"),
                          ("Restore", lambda: self.core.window_cmd(pid, "restore"), "soft"),
                          ("Resize", lambda: self.resize(pid), "soft"),
                          ("Restart", lambda: self.core.restart_client(pid), "soft"),
                          ("Close", lambda: self.core.close_client(pid), "danger")]:
            button(row, t, cmd, w=82, kind=k).pack(side="left", padx=3)
        return {"frame": f, "lab": lab}
 
    def resize(self, pid):
        s = simpledialog.askstring(APP_NAME, "New size (WIDTHxHEIGHT), e.g. 800x450:", parent=self.app)
        m = re.fullmatch(r"\s*(\d{3,5})\s*[xX]\s*(\d{3,5})\s*", s or "")
        if m:
            self.core.resize(pid, int(m.group(1)), int(m.group(2)))
        elif s:
            messagebox.showerror(APP_NAME, "Use the format 800x450.")
 
    def refresh(self):
        cl = self.core.snapshot()
        alive = {c["pid"] for c in cl}
        for pid in list(self.cards):
            if pid not in alive:
                self.cards.pop(pid)["frame"].destroy()
        for c in cl:
            if c["pid"] not in self.cards:
                self.cards[c["pid"]] = self.make_card(c)
            lab = self.cards[c["pid"]]["lab"]
            lab["info"].configure(text=f"Game: {dest_label(c['dest'])}    PID: {c['pid']}    Uptime: {fmt_dur(time.time() - c['start'])}")
            lab["res"].configure(text=f"CPU: {c['cpu']:.1f}%    RAM: {fmt_mb(c['rss'])}    FPS: n/a (not reliably readable)")
            conn = "Not responding" if c["hung"] >= 1 else "Running"
            lab["win"].configure(text=f"Window: {win_state(c['hwnd'])}    Connection: {conn}")
        if cl:
            self.empty.pack_forget()
        else:
            self.empty.pack(pady=40)
        self.stat["clients"].configure(text=str(len(cl)))
        self.stat["ram"].configure(text=fmt_mb(sum(c["rss"] for c in cl)))
        self.stat["cpu"].configure(text=f"{sum(c['cpu'] for c in cl):.1f}%")
        self.stat["running"].configure(text=str(len({c["account_id"] for c in cl})))
        self.stat["failed"].configure(text=str(self.core.failed))
 
 
class AccountsPage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x")
        self.search = ctk.CTkEntry(bar, placeholder_text="Search accounts", width=200)
        self.search.pack(side="left", padx=3)
        self.search.bind("<KeyRelease>", lambda e: self.rebuild())
        self.sort = ctk.CTkOptionMenu(bar, values=["Name", "Last used", "Group", "Robux", "Main first"],
                                      width=110, command=lambda v: self.rebuild())
        self.sort.pack(side="left", padx=3)
        self.gfilter = ctk.CTkOptionMenu(bar, values=["All groups"], width=130, command=lambda v: self.rebuild())
        self.gfilter.pack(side="left", padx=3)
        bar2 = ctk.CTkFrame(self, fg_color="transparent")
        bar2.pack(fill="x", pady=8)
        for t, f, k in [("Add account", self.add, "accent"), ("Edit", self.edit, "soft"),
                        ("Set MAIN", self.set_main, "soft"), ("New group", self.new_group, "soft"),
                        ("Select all", self.select_all, "soft"), ("Clear", self.clear_sel, "soft"),
                        ("Check status", self.check, "soft"), ("Remove", self.remove, "danger")]:
            button(bar2, t, f, kind=k).pack(side="left", padx=3)
        self.list = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.list.pack(fill="both", expand=True)
        self.vars = {}
        self.rebuild()
 
    def groups(self):
        return [r[0] for r in self.core.db.all("SELECT name FROM groups ORDER BY name")]
 
    def rebuild(self):
        for w in self.list.winfo_children():
            w.destroy()
        self.gfilter.configure(values=["All groups", "Ungrouped"] + self.groups())
        rows = self.core.db.all("SELECT a.*, g.name AS gname FROM accounts a LEFT JOIN groups g ON g.id=a.group_id")
        s, g = self.search.get().strip().lower(), self.gfilter.get()
        rows = [r for r in rows
                if (not s or s in (r["alias"] or r["username"]).lower() or s in (r["label"] or "").lower())
                and (g == "All groups" or (r["gname"] or "Ungrouped") == g)]
        key = self.sort.get()
        keyf = {"Name": lambda r: (r["alias"] or r["username"]).lower(),
                "Last used": lambda r: -(r["last_used"] or 0),
                "Group": lambda r: (r["gname"] or "~").lower(),
                "Robux": lambda r: -(r["robux"] or 0),
                "Main first": lambda r: (-r["is_main"], (r["alias"] or r["username"]).lower())}[key]
        rows.sort(key=keyf)
        self.vars = {}
        for r in rows:
            f = panel(self.list)
            f.pack(fill="x", pady=4, padx=2)
            v = ctk.BooleanVar(value=r["id"] in self.app.selected)
            self.vars[r["id"]] = v
            ctk.CTkCheckBox(f, text="", variable=v, width=24, command=lambda i=r["id"], v=v: self.toggle(i, v)).pack(side="left", padx=(12, 4), pady=10)
            img = self.app.avatar(r["id"], r["user_id"])
            ctk.CTkLabel(f, text="" if img else "●", image=img, width=40, text_color=ACCENT).pack(side="left")
            name = r["alias"] or r["username"]
            ctk.CTkLabel(f, text=name + ("  ★ MAIN" if r["is_main"] else ""), text_color=r["color"] or ("#111827", "#e5e7eb"),
                         font=ctk.CTkFont(size=14, weight="bold"), width=190, anchor="w").pack(side="left", padx=8)
            lu = datetime.fromtimestamp(r["last_used"]).strftime("%Y-%m-%d %H:%M") if r["last_used"] else "never"
            rb = f"R$ {r['robux']:,}" if r["robux"] is not None else "R$ n/a"
            ctk.CTkLabel(f, text=f"{r['label'] or '-'}  |  {r['gname'] or 'Ungrouped'}  |  {rb}  |  {r['status']}  |  last used {lu}",
                         text_color=MUTED).pack(side="left", padx=8)
 
    def toggle(self, i, v):
        (self.app.selected.add if v.get() else self.app.selected.discard)(i)
 
    def select_all(self):
        for i, v in self.vars.items():
            v.set(True)
            self.app.selected.add(i)
 
    def clear_sel(self):
        for i, v in self.vars.items():
            v.set(False)
        self.app.selected.clear()
 
    def sel_ids(self):
        return [i for i in self.vars if self.vars[i].get()]
 
    def new_group(self):
        n = simpledialog.askstring(APP_NAME, "Group name:", parent=self.app)
        if n and n.strip():
            self.core.db.q("INSERT OR IGNORE INTO groups(name) VALUES(?)", (n.strip(),))
            self.rebuild()
 
    def set_main(self):
        ids = self.sel_ids()
        if len(ids) != 1:
            messagebox.showinfo(APP_NAME, "Select exactly one account.")
            return
        self.core.db.q("UPDATE accounts SET is_main=0")
        self.core.db.q("UPDATE accounts SET is_main=1 WHERE id=?", (ids[0],))
        self.rebuild()
 
    def add(self):
        top = ctk.CTkToplevel(self.app)
        top.title("Add account")
        top.geometry("560x330")
        msg = ("Adds an account by importing its .ROBLOSECURITY session cookie.\n\n"
               "SECURITY: that cookie is a full login for the account. RoManager encrypts it with\n"
               "Windows DPAPI (only this Windows user on this PC can decrypt it) and never shows,\n"
               "logs or exports it. Only import accounts you own. Never share this cookie with anyone.")
        ctk.CTkLabel(top, text=msg, justify="left", text_color=MUTED).pack(padx=18, pady=(18, 8), anchor="w")
        e = ctk.CTkEntry(top, show="•", width=500, placeholder_text="Paste .ROBLOSECURITY value")
        e.pack(pady=6)
        status = ctk.CTkLabel(top, text="")
        status.pack()
 
        def go():
            raw = e.get().strip().strip('"')
            if raw.startswith("_|WARNING") is False and len(raw) < 100:
                status.configure(text="That does not look like a .ROBLOSECURITY cookie.", text_color=DANGER)
                return
            status.configure(text="Verifying with Roblox...", text_color=MUTED)
 
            def work():
                me = whoami(raw)
                return me, get_robux(raw, me["id"])
 
            def done(res, err):
                if err:
                    status.configure(text=str(err), text_color=DANGER)
                    return
                me, rb = res
                if self.core.db.one("SELECT 1 FROM accounts WHERE user_id=?", (me["id"],)):
                    status.configure(text="That account is already added.", text_color=DANGER)
                    return
                self.core.db.q("INSERT INTO accounts(user_id,username,cookie_enc,status,robux,created) VALUES(?,?,?,?,?,?)",
                               (me["id"], me["name"], dpapi_protect(raw.encode()), "Valid", rb, time.time()))
                e.delete(0, "end")
                top.destroy()
                self.rebuild()
 
            self.app.bg(work, done)
 
        button(top, "Verify and add", go, w=140, kind="accent").pack(pady=10)
        top.after(150, top.grab_set)
 
    def edit(self):
        ids = self.sel_ids()
        if len(ids) != 1:
            messagebox.showinfo(APP_NAME, "Select exactly one account.")
            return
        r = self.core.db.one("SELECT a.*, g.name AS gname FROM accounts a LEFT JOIN groups g ON g.id=a.group_id WHERE a.id=?", (ids[0],))
        top = ctk.CTkToplevel(self.app)
        top.title("Edit account")
        top.geometry("360x340")
        alias = ctk.CTkEntry(top, width=280, placeholder_text="Display name")
        alias.pack(pady=(18, 6))
        alias.insert(0, r["alias"] or "")
        label = ctk.CTkEntry(top, width=280, placeholder_text="Label")
        label.pack(pady=6)
        label.insert(0, r["label"] or "")
        grp = ctk.CTkOptionMenu(top, values=["Ungrouped"] + self.groups(), width=280)
        grp.set(r["gname"] or "Ungrouped")
        grp.pack(pady=6)
        color = {"v": r["color"]}
        cb = button(top, "Choose color", lambda: pick(), w=280)
        cb.pack(pady=6)
 
        def pick():
            c = colorchooser.askcolor(parent=top)[1]
            if c:
                color["v"] = c
 
        def clear_color():
            color["v"] = None
 
        button(top, "Clear color", clear_color, w=280).pack(pady=6)
 
        def save():
            gid = None
            if grp.get() != "Ungrouped":
                gid = self.core.db.one("SELECT id FROM groups WHERE name=?", (grp.get(),))[0]
            self.core.db.q("UPDATE accounts SET alias=?, label=?, color=?, group_id=? WHERE id=?",
                           (alias.get().strip() or None, label.get().strip() or None, color["v"], gid, ids[0]))
            top.destroy()
            self.rebuild()
 
        button(top, "Save", save, kind="accent").pack(pady=12)
        top.after(150, top.grab_set)
 
    def remove(self):
        ids = self.sel_ids()
        if not ids or not messagebox.askyesno(APP_NAME, f"Securely remove {len(ids)} account(s)? The stored session is overwritten and deleted."):
            return
        for i in ids:
            self.core.db.q("UPDATE accounts SET cookie_enc=? WHERE id=?", (os.urandom(256), i))
            self.core.db.q("DELETE FROM accounts WHERE id=?", (i,))
            self.app.selected.discard(i)
        self.rebuild()
 
    def check(self):
        ids = self.sel_ids() or [r[0] for r in self.core.db.all("SELECT id FROM accounts")]
 
        def work():
            for i in ids:
                a = self.core.db.one("SELECT user_id, cookie_enc FROM accounts WHERE id=?", (i,))
                try:
                    ck_ = dpapi_unprotect(a["cookie_enc"]).decode()
                    me = whoami(ck_)
                    self.core.db.q("UPDATE accounts SET status='Valid', robux=?, username=? WHERE id=?",
                                   (get_robux(ck_, me["id"]), me["name"], i))
                except AuthExpired:
                    self.core.db.q("UPDATE accounts SET status='Expired' WHERE id=?", (i,))
                except Exception as e:
                    self.core.db.q("UPDATE accounts SET status=? WHERE id=?", (f"Error: {e}"[:40], i))
 
        self.app.bg(work, lambda r, e: self.rebuild())
 
 
class PlayPage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.seen = 0
        top = panel(self)
        top.pack(fill="x")
        ctk.CTkLabel(top, text="Destination (place ID, experience link, private server link or server link)",
                     text_color=MUTED).pack(anchor="w", padx=14, pady=(10, 2))
        row = ctk.CTkFrame(top, fg_color="transparent")
        row.pack(fill="x", padx=12)
        self.dest = ctk.CTkEntry(row, width=520)
        self.dest.pack(side="left", padx=2)
        self.dest.insert(0, self.core.db.get("default_dest"))
        button(row, "Save favourite", self.fav, w=110).pack(side="left", padx=4)
        row2 = ctk.CTkFrame(top, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=10)
        ctk.CTkLabel(row2, text="Delay between launches (s)").pack(side="left", padx=4)
        self.delay = ctk.CTkEntry(row2, width=60)
        self.delay.pack(side="left")
        self.delay.insert(0, self.core.db.get("delay"))
        self.multi = ctk.CTkSwitch(row2, text="Multi-instance", command=self.toggle_multi)
        self.multi.pack(side="left", padx=18)
        if self.core.mutex:
            self.multi.select()
        self.sel = ctk.CTkLabel(row2, text="", text_color=MUTED)
        self.sel.pack(side="left", padx=8)
        row3 = ctk.CTkFrame(top, fg_color="transparent")
        row3.pack(fill="x", padx=12, pady=(0, 12))
        button(row3, "Launch selected", self.launch, w=130, kind="accent").pack(side="left", padx=3)
        button(row3, "Pause", lambda: self.core.pause_ev.clear(), w=80).pack(side="left", padx=3)
        button(row3, "Resume", lambda: self.core.pause_ev.set(), w=80).pack(side="left", padx=3)
        button(row3, "Cancel", self.cancel, w=80, kind="danger").pack(side="left", padx=3)
        self.err = ctk.CTkLabel(top, text="", text_color=DANGER)
        self.err.pack(anchor="w", padx=14, pady=(0, 8))
        self.prog = ctk.CTkProgressBar(self)
        self.prog.pack(fill="x", pady=8)
        self.prog.set(0)
        mid = ctk.CTkFrame(self, fg_color="transparent")
        mid.pack(fill="both", expand=True)
        mid.grid_columnconfigure((0, 1, 2), weight=1, uniform="c")
        mid.grid_rowconfigure(0, weight=1)
        self.favs = ctk.CTkScrollableFrame(mid, label_text="Favourites", fg_color=PANEL)
        self.favs.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        self.hist = ctk.CTkScrollableFrame(mid, label_text="Recent destinations", fg_color=PANEL)
        self.hist.grid(row=0, column=1, sticky="nsew", padx=4)
        self.log = ctk.CTkTextbox(mid, fg_color=PANEL, state="disabled")
        self.log.grid(row=0, column=2, sticky="nsew", padx=(4, 0))
        self.lists_key = None
 
    def toggle_multi(self):
        on = bool(self.multi.get())
        self.core.db.set("multi", "1" if on else "0")
        m = self.core.set_multi(on)
        self.core.log(m)
        if on and not self.core.mutex:
            self.multi.deselect()
            self.core.db.set("multi", "0")
            messagebox.showwarning(APP_NAME, m)
 
    def fav(self):
        try:
            d = parse_dest(self.dest.get())
        except ValueError as e:
            self.err.configure(text=str(e))
            return
        n = simpledialog.askstring(APP_NAME, "Name for this favourite:", parent=self.app) or str(d["place_id"])
        self.core.db.q("INSERT INTO favourites(place_id,name) VALUES(?,?) ON CONFLICT(place_id) DO UPDATE SET name=excluded.name",
                       (d["place_id"], n.strip()))
        self.lists_key = None
 
    def launch(self):
        self.err.configure(text="")
        try:
            d = parse_dest(self.dest.get())
            delay = float(self.delay.get())
            if not 0 <= delay <= 600:
                raise ValueError("Delay must be between 0 and 600 seconds.")
        except ValueError as e:
            msg = str(e)
            self.err.configure(text="Invalid delay." if msg.startswith("could not convert") else msg)
            return
        ids = [i for i in self.app.selected if self.core.db.one("SELECT 1 FROM accounts WHERE id=?", (i,))]
        if not ids:
            self.err.configure(text="Select at least one account on the Accounts page.")
            return
        try:
            self.core.start_queue(ids, d, delay)
        except RuntimeError as e:
            self.err.configure(text=str(e))
 
    def cancel(self):
        self.core.cancel_ev.set()
        self.core.pause_ev.set()
 
    def refresh(self):
        n = len(self.app.selected)
        self.sel.configure(text=f"{n} account(s) selected")
        q = self.core.qs
        self.prog.set(q["done"] / q["total"] if q["total"] else 0)
        fk = (self.core.db.one("SELECT COUNT(*) FROM favourites")[0], self.core.db.one("SELECT COUNT(*) FROM launch_history")[0])
        if fk != self.lists_key:
            self.lists_key = fk
            for w in self.favs.winfo_children() + self.hist.winfo_children():
                w.destroy()
            for r in self.core.db.all("SELECT * FROM favourites ORDER BY name"):
                button(self.favs, f"{r['name']} ({r['place_id']})", lambda p=r["place_id"]: self.fill(p), w=200).pack(pady=2)
            seen = set()
            for r in self.core.db.all("SELECT dest FROM launch_history ORDER BY ts DESC LIMIT 40"):
                if r["dest"] not in seen and len(seen) < 10:
                    seen.add(r["dest"])
                    button(self.hist, r["dest"], lambda p=r["dest"].split()[0]: self.fill(p), w=200).pack(pady=2)
        if self.seen < len(self.core.logs):
            self.log.configure(state="normal")
            for line in self.core.logs[self.seen:]:
                self.log.insert("end", line + "\n")
            self.log.see("end")
            self.log.configure(state="disabled")
            self.seen = len(self.core.logs)
 
    def fill(self, p):
        self.dest.delete(0, "end")
        self.dest.insert(0, str(p))
 
 
class MonitorPage(Page):
    RANGES = {"1 min": 60, "5 min": 300, "15 min": 900, "1 hour": 3600}
 
    def __init__(self, parent, app):
        super().__init__(parent, app)
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x")
        self.range = ctk.CTkSegmentedButton(bar, values=list(self.RANGES))
        self.range.set("5 min")
        self.range.pack(side="left", padx=3)
        self.client = ctk.CTkOptionMenu(bar, values=["All clients"], width=240)
        self.client.pack(side="left", padx=10)
        self.info = ctk.CTkLabel(self, text="", justify="left", text_color=MUTED, anchor="w")
        self.info.pack(fill="x", pady=8)
        self.cpu = ctk.CTkCanvas(self, height=210, bg="#171a21", highlightthickness=0)
        self.cpu.pack(fill="x", pady=4)
        self.ram = ctk.CTkCanvas(self, height=210, bg="#171a21", highlightthickness=0)
        self.ram.pack(fill="x", pady=4)
 
    @staticmethod
    def draw(cv, series, ymax, title):
        cv.delete("all")
        w, h = cv.winfo_width(), cv.winfo_height()
        if w < 30:
            return
        cv.create_text(10, 8, anchor="nw", fill="#8b93a7", font=("Segoe UI", 9), text=f"{title}   (scale 0 - {ymax:,.0f})")
        top, bot = 30, h - 8
        for f in (0.25, 0.5, 0.75, 1.0):
            y = top + (bot - top) * f
            cv.create_line(0, y, w, y, fill="#232834")
        for pts, color in series:
            step = max(1, len(pts) // 300)
            pts = pts[::step]
            if len(pts) < 2:
                continue
            co = []
            for i, v in enumerate(pts):
                co += [i * (w - 1) / (len(pts) - 1), bot - (bot - top) * min(v, ymax) / ymax]
            cv.create_line(*co, fill=color, width=2)
 
    def refresh(self):
        cl = self.core.snapshot()
        opts = ["All clients"] + [f"{c['pid']} - {c['name']}" for c in cl]
        self.client.configure(values=opts)
        if self.client.get() not in opts:
            self.client.set("All clients")
        rng = self.RANGES[self.range.get()]
        now = time.time()
        s = [x for x in self.core.hist if x["t"] >= now - rng]
        if not s:
            self.info.configure(text="Collecting samples...")
            return
        last = s[-1]
        sel = self.client.get()
        if sel == "All clients":
            rb_cpu = [x["rb_cpu"] for x in s]
            rb_ram = [x["rb_ram"] / 1048576 for x in s]
            extra = f"Roblox clients: {last['count']}"
        else:
            pid = int(sel.split(" ")[0])
            rb_cpu = [x["per"].get(pid, (0, 0))[0] for x in s]
            rb_ram = [x["per"].get(pid, (0, 0))[1] / 1048576 for x in s]
            c = next((c for c in cl if c["pid"] == pid), None)
            extra = f"Selected PID {pid}: uptime {fmt_dur(now - c['start']) if c else '-'}"
        self.info.configure(text=(
            f"System CPU {last['cpu']:.0f}%   |   RAM used {last['ram_used'] / 2**30:.1f} GB of {last['total'] / 2**30:.1f} GB, "
            f"available {last['ram_avail'] / 2**30:.1f} GB   |   Network (system-wide) up {last['up'] / 1024:.0f} KB/s, "
            f"down {last['down'] / 1024:.0f} KB/s\n{extra}   |   App uptime {fmt_dur(now - self.core.started)}"))
        self.draw(self.cpu, [([x["cpu"] for x in s], "#6b7280"), (rb_cpu, ACCENT)], 100, "CPU %  - grey: system, blue: Roblox")
        self.draw(self.ram, [(rb_ram, "#34d399")], max(512, max(rb_ram) * 1.2), "Roblox RAM (MB)")
 
 
class PerfPage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        db = self.core.db
        p = panel(self)
        p.pack(fill="x")
        ctk.CTkLabel(p, text="Preset", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=14, pady=(12, 4))
        self.preset = ctk.CTkSegmentedButton(p, values=["Balanced", "Low resource", "Custom"])
        self.preset.set({"balanced": "Balanced", "low": "Low resource", "custom": "Custom"}[db.get("preset")])
        self.preset.pack(anchor="w", padx=14)
        ctk.CTkLabel(p, justify="left", text_color=MUTED, text=(
            "Balanced: normal priority, no window changes.   Low resource: below-normal priority, 640x360 windows,\n"
            "monitoring at most every 5 s.   Custom: your values below. Uses Windows priority classes and window\n"
            "sizing only. No injection, no memory changes. FPS capping is not offered: Roblox no longer supports it.")
        ).pack(anchor="w", padx=14, pady=8)
        g = ctk.CTkFrame(p, fg_color="transparent")
        g.pack(fill="x", padx=14, pady=(0, 14))
        self.prio = ctk.CTkOptionMenu(g, values=["Normal", "Below normal", "Idle"], width=130)
        self.prio.set(db.get("c_prio"))
        self.w, self.h, self.iv, self.mon = (ctk.CTkEntry(g, width=70) for _ in range(4))
        for e, k in [(self.w, "c_w"), (self.h, "c_h"), (self.iv, "interval"), (self.mon, "monitor")]:
            e.insert(0, db.get(k))
        self.automin = ctk.CTkSwitch(g, text="Minimize clients that are not in the foreground")
        if db.flag("c_automin"):
            self.automin.select()
        for i, (t, wdg) in enumerate([("Priority", self.prio), ("Window width (0 = leave)", self.w),
                                      ("Window height", self.h), ("Monitor interval (s)", self.iv),
                                      ("Arrange on monitor # (0 = primary)", self.mon)]):
            ctk.CTkLabel(g, text=t).grid(row=i, column=0, sticky="w", pady=3)
            wdg.grid(row=i, column=1, sticky="w", padx=10)
        self.automin.grid(row=5, column=0, columnspan=2, sticky="w", pady=6)
        r = ctk.CTkFrame(p, fg_color="transparent")
        r.pack(anchor="w", padx=14, pady=(0, 12))
        button(r, "Save", self.save, kind="accent").pack(side="left", padx=3)
        button(r, "Apply to running clients", lambda: self.core.apply_all(), w=170).pack(side="left", padx=3)
        self.use = ctk.CTkTextbox(self, fg_color=PANEL, state="disabled")
        self.use.pack(fill="both", expand=True, pady=10)
 
    def save(self):
        db = self.core.db
        db.set("preset", {"Balanced": "balanced", "Low resource": "low", "Custom": "custom"}[self.preset.get()])
        db.set("c_prio", self.prio.get())
        db.set("c_automin", "1" if self.automin.get() else "0")
        for e, k in [(self.w, "c_w"), (self.h, "c_h"), (self.iv, "interval"), (self.mon, "monitor")]:
            if re.fullmatch(r"\d{1,4}", e.get().strip()):
                db.set(k, e.get().strip())
        self.core.apply_all()
 
    def refresh(self):
        lines = [f"{c['name']:<24} PID {c['pid']:<7} CPU {c['cpu']:5.1f}%   RAM {fmt_mb(c['rss'])}" for c in self.core.snapshot()]
        self.use.configure(state="normal")
        self.use.delete("1.0", "end")
        self.use.insert("end", "Per-client resource usage\n\n" + ("\n".join(lines) or "No clients running."))
        self.use.configure(state="disabled")
 
 
class SettingsPage(Page):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        db = self.core.db
        sc = ctk.CTkScrollableFrame(self, fg_color="transparent")
        sc.pack(fill="both", expand=True)
 
        def section(t):
            p = panel(sc)
            p.pack(fill="x", pady=6)
            ctk.CTkLabel(p, text=t, font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w", padx=14, pady=(10, 4))
            return p
 
        def switch(p, text, key, cb=None):
            s = ctk.CTkSwitch(p, text=text, command=lambda: (db.set(key, "1" if s.get() else "0"), cb and cb()))
            if db.flag(key):
                s.select()
            s.pack(anchor="w", padx=14, pady=3)
            return s
 
        def entry(p, text, key, w=80):
            f = ctk.CTkFrame(p, fg_color="transparent")
            f.pack(anchor="w", padx=14, pady=3)
            ctk.CTkLabel(f, text=text, width=230, anchor="w").pack(side="left")
            e = ctk.CTkEntry(f, width=w)
            e.insert(0, db.get(key))
            e.pack(side="left")
            e.bind("<FocusOut>", lambda ev: db.set(key, e.get().strip()) if e.get().strip() else None)
            return e
 
        p = section("General")
        switch(p, "Start with Windows", "autostart", self.autostart)
        switch(p, "Start minimized", "start_min")
        f = ctk.CTkFrame(p, fg_color="transparent")
        f.pack(anchor="w", padx=14, pady=(3, 12))
        ctk.CTkLabel(f, text="Theme", width=230, anchor="w").pack(side="left")
        th = ctk.CTkOptionMenu(f, values=["dark", "light", "system"], width=110, command=self.theme)
        th.set(db.get("theme"))
        th.pack(side="left")
        p = section("Launch")
        entry(p, "Default launch delay (s)", "delay")
        entry(p, "Default destination", "default_dest", 280)
        ctk.CTkLabel(p, text="Applied the next time RoManager starts.", text_color=MUTED).pack(anchor="w", padx=14, pady=(0, 10))
        p = section("Recovery")
        switch(p, "Automatic recovery (restart crashed or unresponsive clients)", "auto")
        entry(p, "Maximum restart attempts", "max_attempts")
        entry(p, "Restart delay (s)", "restart_delay")
        ctk.CTkLabel(p, text="Never bypasses kicks or bans: it only relaunches the client you launched.", text_color=MUTED).pack(anchor="w", padx=14, pady=(0, 10))
        p = section("Discord notifications")
        self.wh = ctk.CTkEntry(p, width=420, show="•", placeholder_text="Webhook URL" + (" (saved, hidden)" if db.get("webhook") else ""))
        self.wh.pack(anchor="w", padx=14, pady=4)
        r = ctk.CTkFrame(p, fg_color="transparent")
        r.pack(anchor="w", padx=14)
        button(r, "Save and test", self.save_wh, w=120, kind="accent").pack(side="left", padx=2)
        button(r, "Remove webhook", self.rm_wh, w=130).pack(side="left", padx=2)
        self.whmsg = ctk.CTkLabel(p, text="", text_color=MUTED)
        self.whmsg.pack(anchor="w", padx=14)
        switch(p, "Enable notifications", "wh_on")
        switch(p, "Client crash", "n_crash")
        switch(p, "Unresponsive client", "n_hung")
        switch(p, "Restart", "n_restart")
        switch(p, "Launch completion", "n_launch")
        p = section("Anti-AFK")
        ctk.CTkLabel(p, justify="left", text_color=MUTED, text=(
            "RoManager does not simulate input. Simulated input may not count as player activity and Roblox can\n"
            "disconnect idle sessions at any time, so no AFK guarantee is offered.")).pack(anchor="w", padx=14, pady=(0, 10))
        p = section("Security")
        ctk.CTkLabel(p, justify="left", text_color=MUTED, text=(
            "Session cookies and the webhook are DPAPI-encrypted per field. The master password locks the app\n"
            "at startup; it does not encrypt the database file. Accounts are removed by overwriting the stored secret.")).pack(anchor="w", padx=14)
        r = ctk.CTkFrame(p, fg_color="transparent")
        r.pack(anchor="w", padx=14, pady=10)
        button(r, "Set master password", self.set_pw, w=150, kind="accent").pack(side="left", padx=2)
        button(r, "Remove master password", self.rm_pw, w=170).pack(side="left", padx=2)
 
    def theme(self, v):
        self.core.db.set("theme", v)
        ctk.set_appearance_mode(v)
 
    def autostart(self):
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as k:
                if self.core.db.flag("autostart"):
                    exe = sys.executable if getattr(sys, "frozen", False) else f'"{sys.executable}" "{os.path.abspath(__file__)}"'
                    winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, exe if getattr(sys, "frozen", False) is False else f'"{exe}"')
                else:
                    try:
                        winreg.DeleteValue(k, APP_NAME)
                    except FileNotFoundError:
                        pass
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Could not change startup setting: {e}")
 
    def save_wh(self):
        url = self.wh.get().strip()
        if not WEBHOOK_RE.match(url):
            self.whmsg.configure(text="Not a valid Discord webhook URL.", text_color=DANGER)
            return
        self.whmsg.configure(text="Sending test message...", text_color=MUTED)
 
        def done(ok, err):
            if ok:
                self.core.db.set("webhook", dpapi_protect(url.encode()).hex())
                self.wh.delete(0, "end")
                self.whmsg.configure(text="Webhook saved (test message sent).", text_color="#34d399")
            else:
                self.whmsg.configure(text="Discord rejected the test message. Not saved.", text_color=DANGER)
 
        self.app.bg(lambda: discord_post(url, "RoManager webhook test."), done)
 
    def rm_wh(self):
        self.core.db.set("webhook", "")
        self.whmsg.configure(text="Webhook removed.", text_color=MUTED)
 
    def set_pw(self):
        a = ask_secret(self.app, "Master password", "New master password:")
        if not a:
            return
        if len(a) < 6:
            messagebox.showerror(APP_NAME, "Use at least 6 characters.")
            return
        if ask_secret(self.app, "Master password", "Repeat it:") != a:
            messagebox.showerror(APP_NAME, "Passwords did not match.")
            return
        self.core.db.set("lock_hash", hash_pw(a))
        messagebox.showinfo(APP_NAME, "Master password set. It is asked at startup.")
 
    def rm_pw(self):
        h = self.core.db.get("lock_hash")
        if h and verify_pw(ask_secret(self.app, "Master password", "Current password:") or "", h):
            self.core.db.set("lock_hash", "")
        elif h:
            messagebox.showerror(APP_NAME, "Wrong password.")
 
 
class App(ctk.CTk):
    NAV = ["Home", "Accounts", "Play", "Monitor", "Performance", "Settings"]
 
    def __init__(self, core):
        super().__init__()
        self.core = core
        self.selected = set()
        self.avatars = {}
        self.uiq = queue.Queue()
        ctk.set_appearance_mode(core.db.get("theme"))
        self.title(APP_NAME)
        self.geometry("1240x780")
        self.minsize(1040, 640)
        self.configure(fg_color=BG)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        side = ctk.CTkFrame(self, width=190, fg_color=PANEL, corner_radius=0, border_width=0)
        side.grid(row=0, column=0, sticky="nsw")
        side.grid_propagate(False)
        ctk.CTkLabel(side, text="RoManager", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(22, 18), padx=16, anchor="w")
        self.navb = {}
        for n in self.NAV:
            b = ctk.CTkButton(side, text=n, anchor="w", height=36, corner_radius=8, fg_color="transparent",
                              text_color=("#111827", "#e5e7eb"), hover_color=SOFT, command=lambda n=n: self.show(n))
            b.pack(fill="x", padx=10, pady=2)
            self.navb[n] = b
        self.status = ctk.CTkLabel(side, text="", text_color=MUTED, justify="left")
        self.status.pack(side="bottom", anchor="w", padx=14, pady=14)
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.grid(row=0, column=1, sticky="nsew", padx=18, pady=16)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)
        self.pages = {"Home": HomePage, "Accounts": AccountsPage, "Play": PlayPage, "Monitor": MonitorPage,
                      "Performance": PerfPage, "Settings": SettingsPage}
        self.pages = {n: c(self.content, self) for n, c in self.pages.items()}
        self.current = "Home"
        self.show("Home")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(100, self.pump)
        self.after(1200, self.tick)
        if core.db.flag("start_min"):
            self.iconify()
        if not roblox_installed():
            self.after(500, lambda: messagebox.showwarning(APP_NAME, "Roblox Player was not found for this Windows user. "
                                                           "Install Roblox from roblox.com before launching."))
 
    def show(self, name):
        self.current = name
        self.pages[name].tkraise()
        for n, b in self.navb.items():
            b.configure(fg_color=ACCENT if n == name else "transparent", text_color="#ffffff" if n == name else ("#111827", "#e5e7eb"))
        self.pages[name].refresh()
 
    def pump(self):
        try:
            while True:
                self.uiq.get_nowait()()
        except queue.Empty:
            pass
        self.after(100, self.pump)
 
    def ui(self, fn):
        self.uiq.put(fn)
 
    def bg(self, work, done=None):
        def run():
            try:
                r, err = work(), None
            except Exception as e:
                r, err = None, e
            if done:
                self.ui(lambda: done(r, err))
 
        threading.Thread(target=run, daemon=True).start()
 
    def avatar(self, aid, user_id=None):
        if aid in self.avatars:
            return self.avatars[aid]
        if Image is None:
            return None
        self.avatars[aid] = None
        if user_id is None:
            r = self.core.db.one("SELECT user_id FROM accounts WHERE id=?", (aid,))
            user_id = r[0] if r else None
        if not user_id:
            return None
 
        def work():
            b = get_avatar(user_id)
            return Image.open(io.BytesIO(b)).convert("RGBA") if b else None
 
        def done(img, err):
            if img:
                self.avatars[aid] = ctk.CTkImage(img, img, size=(36, 36))
                if self.current == "Accounts":
                    self.pages["Accounts"].rebuild()
 
        self.bg(work, done)
        return None
 
    def tick(self):
        try:
            self.pages[self.current].refresh()
            n = len(self.core.snapshot())
            self.status.configure(text=f"{n} client(s) running\nup {fmt_dur(time.time() - self.core.started)}")
        except Exception as e:
            self.core.log(f"UI error: {e}")
        self.after(1500, self.tick)
 
    def on_close(self):
        self.core.shutdown()
        self.destroy()
 
 
def unlock(core):
    ok, tries = [False], [0]
    w = ctk.CTk()
    w.title("RoManager locked")
    w.geometry("340x190")
    ctk.CTkLabel(w, text="RoManager is locked", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(20, 8))
    e = ctk.CTkEntry(w, show="•", width=240, placeholder_text="Master password")
    e.pack()
    msg = ctk.CTkLabel(w, text="", text_color=DANGER)
    msg.pack(pady=4)
 
    def go(_=None):
        if verify_pw(e.get(), core.db.get("lock_hash")):
            ok[0] = True
            w.destroy()
        else:
            tries[0] += 1
            msg.configure(text=f"Wrong password ({tries[0]}/5)")
            e.delete(0, "end")
            if tries[0] >= 5:
                w.destroy()
 
    e.bind("<Return>", go)
    button(w, "Unlock", go, kind="accent").pack(pady=6)
    e.focus_set()
    w.mainloop()
    return ok[0]
 
 
def main():
    try:
        core = Core()
    except Exception as e:
        user32.MessageBoxW(0, f"Database unavailable:\n{e}", APP_NAME, 0x10)
        return
    ctk.set_appearance_mode(core.db.get("theme"))
    if core.db.get("lock_hash") and not unlock(core):
        return
    core.start()
    App(core).mainloop()
 
 
if __name__ == "__main__":
    main()
