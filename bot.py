#!/usr/bin/env python3
"""
Kali CyberSec Telegram Bot — All-in-One
=========================================
A single-file Telegram bot for cybersecurity reconnaissance on Kali Linux.

Commands:
  /start            - Welcome message
  /help             - List all commands
  /scan  <url|ip>   - Resolve IP + scan common ports
  /history          - Show previously scanned targets (this session)
  /ferox <url>      - Fast directory brute-force (Feroxbuster)
  /recon <url|ip>   - Full recon: subdomains + ports + tech + dirs + screenshot

Setup:
  1. pip install python-telegram-bot python-dotenv
  2. cp .env.example .env  →  fill BOT_TOKEN and ADMIN_IDS
  3. python bot.py

Required Kali tools (install as needed):
  sudo apt install nmap whatweb feroxbuster seclists -y
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install github.com/tomnomnom/assetfinder@latest
  go install github.com/sensepost/gowitness@latest
"""

# ============================================================
#  Standard library
# ============================================================
import asyncio
import concurrent.futures
import json
import logging
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# ============================================================
#  Third-party
# ============================================================
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
from telegram.constants import ParseMode

# ============================================================
#  Configuration  (replaces config.py)
# ============================================================
load_dotenv()

BOT_TOKEN: str = os.getenv("BOT_TOKEN", "")
_raw_ids = os.getenv("ADMIN_IDS", "")
ADMIN_IDS: set[int] = {int(i.strip()) for i in _raw_ids.split(",") if i.strip()}

if not BOT_TOKEN:
    sys.exit("❌ BOT_TOKEN is not set. Copy .env.example → .env and fill in your token.")

# ============================================================
#  Logging
# ============================================================
logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ============================================================
#  Session memory  (/history command)
# ============================================================
scan_history: dict = {}

# ============================================================
#  Common ports  (/scan command)
# ============================================================
COMMON_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    6379:  "Redis",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

# ============================================================
#  Wordlists  (/ferox + /recon)
# ============================================================
WORDLISTS_GENERAL = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]
WORDLISTS_WORDPRESS = [
    "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

# ============================================================
#  SQLite Database  (/recon persistence)
# ============================================================
DB_PATH = Path(__file__).parent / "recon_results.db"


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    with _get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT    NOT NULL,
                started_at  TEXT    NOT NULL,
                finished_at TEXT,
                status      TEXT    DEFAULT 'running'
            );
            CREATE TABLE IF NOT EXISTS subdomains (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id   INTEGER REFERENCES scans(id),
                subdomain TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ports (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id   INTEGER REFERENCES scans(id),
                host      TEXT, port INTEGER,
                protocol  TEXT, service TEXT, state TEXT
            );
            CREATE TABLE IF NOT EXISTS directories (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id   INTEGER REFERENCES scans(id),
                url       TEXT, status INTEGER
            );
            CREATE TABLE IF NOT EXISTS technologies (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id   INTEGER REFERENCES scans(id),
                tech      TEXT
            );
            CREATE TABLE IF NOT EXISTS screenshots (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id   INTEGER REFERENCES scans(id),
                path      TEXT
            );
        """)


def _new_scan(target: str) -> int:
    with _get_db() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, started_at) VALUES (?, ?)",
            (target, datetime.now().isoformat()),
        )
        return cur.lastrowid


def _finish_scan(scan_id: int) -> None:
    with _get_db() as conn:
        conn.execute(
            "UPDATE scans SET finished_at=?, status='done' WHERE id=?",
            (datetime.now().isoformat(), scan_id),
        )

# ============================================================
#  Shared helpers
# ============================================================

def is_authorized(update: Update) -> bool:
    return update.effective_user.id in ADMIN_IDS


def escape_md(text: str) -> str:
    special = r"\_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{c}" if c in special else c for c in str(text))


def split_text(text: str, limit: int = 4000) -> list[str]:
    chunks = []
    while len(text) > limit:
        at = text.rfind("\n", 0, limit)
        if at == -1:
            at = limit
        chunks.append(text[:at])
        text = text[at:]
    if text:
        chunks.append(text)
    return chunks


def _run_proc(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", f"NOT_FOUND: {cmd[0]}", -2


def _first_wordlist(candidates: list[str]) -> str | None:
    return next((w for w in candidates if os.path.isfile(w)), None)


# ============================================================
#  /scan — socket-based port scanner
# ============================================================

def _check_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _scan_ports_sync(ip: str) -> dict[int, bool]:
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        fmap = {ex.submit(_check_port, ip, p): p for p in COMMON_PORTS}
        for f in concurrent.futures.as_completed(fmap):
            results[fmap[f]] = f.result()
    return results


# ============================================================
#  /recon sub-tasks
# ============================================================

def _recon_subdomains(domain: str, scan_id: int) -> list[str]:
    subs: set[str] = set()
    for tool, cmd in [
        ("subfinder",   ["subfinder", "-d", domain, "-silent"]),
        ("assetfinder", ["assetfinder", "--subs-only", domain]),
    ]:
        if not shutil.which(tool):
            continue
        stdout, _, rc = _run_proc(cmd, timeout=90)
        if rc == 0:
            for line in stdout.splitlines():
                line = line.strip().lower()
                if line and domain in line:
                    subs.add(line)
            if subs:
                break
    if subs:
        with _get_db() as conn:
            conn.executemany(
                "INSERT INTO subdomains (scan_id, subdomain) VALUES (?, ?)",
                [(scan_id, s) for s in subs],
            )
    return sorted(subs)


def _recon_nmap(host: str, scan_id: int) -> list[dict]:
    if not shutil.which("nmap"):
        return []
    stdout, _, rc = _run_proc(
        ["nmap", "-T4", "-F", "-n", "-sV", "--open", "-oX", "-", host],
        timeout=120,
    )
    if rc != 0:
        return []
    ports = []
    for m in re.finditer(
        r'<port protocol="(\w+)" portid="(\d+)">'
        r'.*?<state state="(\w+)".*?/>'
        r'(?:.*?<service name="([^"]*)")?',
        stdout, re.DOTALL,
    ):
        if m.group(3) == "open":
            ports.append({
                "host": host, "protocol": m.group(1),
                "port": int(m.group(2)), "state": m.group(3),
                "service": m.group(4) or "unknown",
            })
    if ports:
        with _get_db() as conn:
            conn.executemany(
                "INSERT INTO ports (scan_id,host,port,protocol,service,state) "
                "VALUES (?,?,?,?,?,?)",
                [(scan_id, p["host"], p["port"], p["protocol"],
                  p["service"], p["state"]) for p in ports],
            )
    return ports


def _recon_whatweb(url: str, scan_id: int) -> list[str]:
    if not shutil.which("whatweb"):
        return []
    stdout, _, rc = _run_proc(["whatweb", "--log-json=-", "--quiet", url], timeout=60)
    techs: list[str] = []
    if rc == 0 and stdout.strip():
        try:
            data = json.loads(stdout.strip().splitlines()[-1])
            if isinstance(data, list):
                data = data[0]
            techs = list(data.get("plugins", {}).keys())
        except Exception:
            techs = re.findall(r'\[([^\[\]]+)\]', stdout)
    if techs:
        with _get_db() as conn:
            conn.executemany(
                "INSERT INTO technologies (scan_id, tech) VALUES (?, ?)",
                [(scan_id, t) for t in techs],
            )
    return techs


def _recon_feroxbuster(url: str, scan_id: int, techs: list[str]) -> list[dict]:
    if not shutil.which("feroxbuster"):
        return []
    is_wp = any("wordpress" in t.lower() or "wp" in t.lower() for t in techs)
    wordlist = _first_wordlist(WORDLISTS_WORDPRESS if is_wp else WORDLISTS_GENERAL)
    if not wordlist:
        return []
    stdout, _, _ = _run_proc(
        [
            "feroxbuster", "--url", url, "--wordlist", wordlist,
            "--quiet", "--no-state", "--no-recursion",
            "--threads", "50", "--timeout", "10",
            "--status-codes", "200,204,301,302,307,401,403",
            "--output", "/dev/stdout",
        ],
        timeout=300,
    )
    found = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[0].isdigit():
            found.append({"status": int(parts[0]), "url": parts[-1]})
        elif line.startswith("http"):
            found.append({"status": 0, "url": line})
    if found:
        with _get_db() as conn:
            conn.executemany(
                "INSERT INTO directories (scan_id, url, status) VALUES (?, ?, ?)",
                [(scan_id, d["url"], d["status"]) for d in found],
            )
    return found


def _recon_gowitness(url: str, scan_id: int) -> str | None:
    if not shutil.which("gowitness"):
        return None
    out_dir = Path(__file__).parent / "screenshots"
    out_dir.mkdir(exist_ok=True)
    _, _, rc = _run_proc(
        ["gowitness", "single", "--url", url, "--screenshot-path", str(out_dir)],
        timeout=60,
    )
    if rc == 0:
        imgs = sorted(out_dir.glob("*.png"), key=lambda p: p.stat().st_mtime)
        if imgs:
            path = str(imgs[-1])
            with _get_db() as conn:
                conn.execute(
                    "INSERT INTO screenshots (scan_id, path) VALUES (?, ?)",
                    (scan_id, path),
                )
            return path
    return None


def _run_full_recon(target: str, progress_cb=None) -> dict:
    """Orchestrate all recon tools in two parallel phases."""
    def _cb(msg):
        logger.info(msg)
        if progress_cb:
            progress_cb(msg)

    _init_db()
    scan_id = _new_scan(target)

    parsed = urlparse(target if "://" in target else f"http://{target}")
    url    = f"{parsed.scheme}://{parsed.netloc or parsed.path}"
    host   = parsed.hostname or target

    _cb(f"🚀 Recon started — scan_id={scan_id}")

    # Phase 1: subdomains + nmap + whatweb (parallel)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        f_subs = pool.submit(_recon_subdomains, host, scan_id)
        f_nmap = pool.submit(_recon_nmap, host, scan_id)
        f_tech = pool.submit(_recon_whatweb, url, scan_id)
        concurrent.futures.wait([f_subs, f_nmap, f_tech])

    subs  = f_subs.result() if not f_subs.exception() else []
    ports = f_nmap.result() if not f_nmap.exception() else []
    techs = f_tech.result() if not f_tech.exception() else []
    _cb(f"✅ Phase 1 — subs:{len(subs)} ports:{len(ports)} techs:{len(techs)}")

    # Phase 2: feroxbuster + gowitness (parallel)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        f_dirs   = pool.submit(_recon_feroxbuster, url, scan_id, techs)
        f_screen = pool.submit(_recon_gowitness, url, scan_id)
        concurrent.futures.wait([f_dirs, f_screen])

    dirs   = f_dirs.result()   if not f_dirs.exception()   else []
    screen = f_screen.result() if not f_screen.exception() else None
    _cb(f"✅ Phase 2 — dirs:{len(dirs)} screenshot:{'yes' if screen else 'no'}")

    _finish_scan(scan_id)
    return {
        "scan_id": scan_id, "target": target,
        "started_at": datetime.now().isoformat(),
        "subdomains": subs, "ports": ports,
        "techs": techs, "dirs": dirs, "screenshot": screen,
    }


def _format_recon_report(r: dict) -> str:
    subs  = r.get("subdomains", [])
    ports = r.get("ports", [])
    techs = r.get("techs", [])
    dirs  = r.get("dirs", [])
    lines = [
        f"🛡  RECON REPORT — {r['target']}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🆔 Scan ID  : {r['scan_id']}",
        f"🕒 Started  : {r.get('started_at','?')}",
        "",
        f"🌐 SUBDOMAINS ({len(subs)})",
        *([f"  • {s}" for s in subs[:30]] + (["  …more"] if len(subs) > 30 else [])
          or ["  None found"]),
        "",
        f"🔌 OPEN PORTS ({len(ports)})",
        *([f"  • {p['port']}/{p['protocol']}  {p['service']}" for p in ports]
          or ["  None found"]),
        "",
        f"🧪 TECHNOLOGIES ({len(techs)})",
        *([f"  • {t}" for t in techs[:20]] or ["  None detected"]),
        "",
        f"📂 DIRECTORIES ({len(dirs)})",
        *([f"  • [{d.get('status','?')}] {d['url']}" for d in dirs[:40]]
          + (["  …more"] if len(dirs) > 40 else [])
          or ["  None found"]),
        "",
        f"📸 SCREENSHOT : {'Saved ✅' if r.get('screenshot') else 'N/A'}",
        f"💾 DB         : {DB_PATH}",
    ]
    return "\n".join(lines)


# ============================================================
#  Bot command handlers
# ============================================================

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await update.message.reply_text("⛔ Unauthorized.")
        return
    await update.message.reply_text(
        "👾 *Kali CyberSec Bot* is online\\!\n\nUse /help to see all commands\\.",
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await update.message.reply_text("⛔ Unauthorized.")
        return
    await update.message.reply_text(
        "📖 *Available Commands*\n\n"
        "🔍 *Recon*\n"
        "/scan \\<url\\|ip\\> — Port scan \\(18 common ports\\)\n"
        "/ferox \\<url\\> — Directory bruteforce\n"
        "/recon \\<url\\|ip\\> — Full recon pipeline\n"
        "/history — Previously scanned targets",
        parse_mode=ParseMode.MARKDOWN_V2,
    )


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await update.message.reply_text("⛔ Unauthorized.")
        return
    if not context.args:
        await update.message.reply_text("ℹ️ Usage: /scan <url or ip>")
        return

    raw = context.args[0].strip()
    hostname = raw.replace("https://", "").replace("http://", "").split("/")[0]

    await update.message.reply_text(
        f"🔍 Scanning `{escape_md(hostname)}`\\.\\.\\. please wait\\.",
        parse_mode=ParseMode.MARKDOWN_V2,
    )

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        await update.message.reply_text(
            f"❌ Could not resolve: `{escape_md(hostname)}`",
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return

    loop = asyncio.get_event_loop()
    port_results = await loop.run_in_executor(None, _scan_ports_sync, ip)

    scanned_at   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    open_ports   = {p: COMMON_PORTS[p] for p, ok in port_results.items() if ok}
    closed_ports = {p: COMMON_PORTS[p] for p, ok in port_results.items() if not ok}

    scan_history[hostname] = {
        "ip": ip, "open_ports": open_ports,
        "closed_ports": closed_ports, "scanned_at": scanned_at,
    }

    open_lines   = "\n".join(f"  ✅ `{str(p):<6}` — {escape_md(s)}"
                              for p, s in sorted(open_ports.items())) or "  _None_"
    closed_lines = "\n".join(f"  ❌ `{str(p):<6}` — {escape_md(s)}"
                              for p, s in sorted(closed_ports.items())) or "  _None_"

    report = (
        f"🛡 *Scan Report*\n━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 *Target:* `{escape_md(hostname)}`\n"
        f"📍 *IP:* `{escape_md(ip)}`\n"
        f"🕒 *Scanned:* `{escape_md(scanned_at)}`\n\n"
        f"🔓 *Open Ports \\({len(open_ports)}\\)*\n{open_lines}\n\n"
        f"🔒 *Closed Ports \\({len(closed_ports)}\\)*\n{closed_lines}"
    )
    for chunk in split_text(report):
        await update.message.reply_text(chunk, parse_mode=ParseMode.MARKDOWN_V2)


async def cmd_history(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await update.message.reply_text("⛔ Unauthorized.")
        return
    if not scan_history:
        await update.message.reply_text(
            "📭 No scans yet\\. Use /scan to start\\.",
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return
    lines = ["📋 *Scan History*\n━━━━━━━━━━━━━━━━━━━━"]
    for host, data in scan_history.items():
        n = len(data["open_ports"])
        summary = ", ".join(f"`{p}`" for p in sorted(data["open_ports"])) or "_none_"
        lines.append(
            f"\n🌐 *{escape_md(host)}*\n"
            f"  📍 IP: `{escape_md(data['ip'])}`\n"
            f"  🕒 {escape_md(data['scanned_at'])}\n"
            f"  ✅ Open \\({n}\\): {summary}"
        )
    for chunk in split_text("\n".join(lines)):
        await update.message.reply_text(chunk, parse_mode=ParseMode.MARKDOWN_V2)


async def cmd_ferox(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await update.message.reply_text("⛔ Unauthorized.")
        return
    if not context.args:
        await update.message.reply_text(
            "ℹ️ Usage: /ferox <url>\nExample: /ferox http://192.168.1.10"
        )
        return
    if not shutil.which("feroxbuster"):
        await update.message.reply_text(
            "❌ feroxbuster not installed.\n"
            "Run: sudo apt install feroxbuster -y"
        )
        return
    wordlist = _first_wordlist(WORDLISTS_GENERAL)
    if not wordlist:
        await update.message.reply_text(
            "❌ No wordlist found.\nRun: sudo apt install seclists -y"
        )
        return

    url = context.args[0].strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    await update.message.reply_text(
        f"🕷 Feroxbuster on `{escape_md(url)}`\\.\\.\\. please wait\\.",
        parse_mode=ParseMode.MARKDOWN_V2,
    )

    loop = asyncio.get_event_loop()
    stdout, stderr, _ = await loop.run_in_executor(
        None,
        lambda: _run_proc(
            ["feroxbuster", "--url", url, "--wordlist", wordlist,
             "--quiet", "--no-state", "--threads", "20",
             "--timeout", "10", "--depth", "2",
             "--status-codes", "200,204,301,302,307,401,403"],
            timeout=300,
        ),
    )

    found = []
    for line in stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            found.append(line)

    if not found:
        await update.message.reply_text(
            f"📭 No paths found on `{escape_md(url)}`\\.",
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return

    header = (
        f"🕷 *Feroxbuster Results*\n━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 *Target:* `{escape_md(url)}`\n"
        f"📂 *Found:* {len(found)} path\\(s\\)\n\n"
    )
    body = "\n".join(escape_md(l) for l in found)
    for chunk in split_text(header + body):
        await update.message.reply_text(chunk, parse_mode=ParseMode.MARKDOWN_V2)


async def cmd_recon(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await update.message.reply_text("⛔ Unauthorized.")
        return
    if not context.args:
        await update.message.reply_text(
            "ℹ️ Usage: /recon <url or ip>\n"
            "Example: /recon http://192.168.1.10"
        )
        return

    target = context.args[0].strip()
    status_msg = await update.message.reply_text(
        f"🚀 Full recon started on `{escape_md(target)}`\\.\\.\\.\n"
        f"⏳ Phase 1: subdomains \\+ ports \\+ tech profiling…",
        parse_mode=ParseMode.MARKDOWN_V2,
    )

    progress_queue: asyncio.Queue = asyncio.Queue()

    # Capture the loop HERE (in the async context) so the worker thread
    # can safely call run_coroutine_threadsafe without get_event_loop()
    loop = asyncio.get_event_loop()

    def progress_cb(msg: str) -> None:
        asyncio.run_coroutine_threadsafe(progress_queue.put(msg), loop)

    recon_future = loop.run_in_executor(None, _run_full_recon, target, progress_cb)

    while not recon_future.done():
        try:
            msg = await asyncio.wait_for(progress_queue.get(), timeout=5.0)
            try:
                await status_msg.edit_text(
                    escape_md(msg), parse_mode=ParseMode.MARKDOWN_V2
                )
            except Exception:
                pass
        except asyncio.TimeoutError:
            pass

    try:
        results = await recon_future
    except Exception as exc:
        await update.message.reply_text(f"❌ Recon failed: {escape_md(str(exc))}",
                                        parse_mode=ParseMode.MARKDOWN_V2)
        return

    report = _format_recon_report(results)
    await update.message.reply_text("🏁 *Recon Complete\\!*",
                                    parse_mode=ParseMode.MARKDOWN_V2)
    for chunk in split_text(report):
        await update.message.reply_text(
            f"```\n{chunk}\n```", parse_mode=ParseMode.MARKDOWN_V2
        )

    screenshot = results.get("screenshot")
    if screenshot and Path(screenshot).exists():
        try:
            with open(screenshot, "rb") as img:
                await update.message.reply_photo(
                    photo=img, caption=f"📸 Screenshot of {target}"
                )
        except Exception as exc:
            logger.warning("Could not send screenshot: %s", exc)


# ============================================================
#  Main
# ============================================================

def main() -> None:
    if not ADMIN_IDS:
        logger.warning("ADMIN_IDS is empty — no one can use the bot! Set it in .env")

    logger.info("Authorized IDs: %s", ADMIN_IDS)

    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start",   cmd_start))
    app.add_handler(CommandHandler("help",    cmd_help))
    app.add_handler(CommandHandler("scan",    cmd_scan))
    app.add_handler(CommandHandler("history", cmd_history))
    app.add_handler(CommandHandler("ferox",   cmd_ferox))
    app.add_handler(CommandHandler("recon",   cmd_recon))

    logger.info("Bot started. Press Ctrl+C to stop.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()

