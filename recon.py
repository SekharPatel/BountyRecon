#!/usr/bin/env python3
"""
recon.py.py

Program-aware recon pipeline for authorized security testing / bug bounty work.

What it does:
- Reads one TXT file per program from a targets/ directory
- Treats SQLite as the source of truth
- Keeps each program fully separated by program_id
- Runs one scan cycle per invocation:
    subfinder -> compare with previous results -> httpx alive check -> [naabu + katana] (parallel) -> nuclei -> Telegram
- Saves all output under per-program folders

Run it from a Linux service or timer to control scheduling externally.

Configuration:
  All settings are loaded from a .env file beside the script.
  Copy .env.example to .env and edit it before running.
  On first run (no targets found), the script will prompt you for a domain.

    .env keys:
    ROOT_DIR             - Directory for all the outputs.
    SUBFINDER_BIN        - Path to subfinder binary (default: subfinder)
    HTTPX_BIN            - Path to httpx binary (default: httpx)
    NAABU_BIN            - Path to naabu binary (default: naabu)
    NUCLEI_BIN           - Path to nuclei binary (default: nuclei)
    NUCLEI_ENABLED       - Enable/disable nuclei (default: true)
    NUCLEI_SEVERITIES    - Nuclei severity filter (default: medium,high,critical)
    KATANA_BIN           - Path to katana binary (default: katana)
    KATANA_ENABLED       - Enable/disable katana (default: true)
    SUBFINDER_TIMEOUT    - Subfinder timeout in seconds (default: 3600)
    HTTPX_TIMEOUT        - HTTPX timeout in seconds (default: 1800)
    NAABU_TIMEOUT        - Naabu timeout in seconds (default: 3600)
    NUCLEI_TIMEOUT       - Nuclei timeout in seconds (default: 3600)
    KATANA_TIMEOUT       - Katana crawling timeout in seconds (default: 3600)
    KATANA_DEPTH         - Katana crawl depth (default: 3)
    KATANA_HEADLESS      - Enable katana headless browser mode (default: false)
    KATANA_FIELD_SCOPE   - Field scope for katana (-fs) (default: rdn)
    KATANA_CUSTOM_SCOPE  - Custom scope for katana (-cs) (default: empty)
    ASNMAP_BIN           - Path to asnmap binary (default: asnmap)
    MAPCIDR_BIN          - Path to mapcidr binary (default: mapcidr)
    ASN_ENABLED          - Enable ASN -> CIDR -> IP recon stage (default: true)
    ASN_TIMEOUT          - asnmap timeout in seconds (default: 900)
    MAPCIDR_TIMEOUT      - mapcidr timeout in seconds (default: 300)
    ASN_ALIVE_TIMEOUT    - naabu alive-check timeout for ASN IPs in seconds (default: 1800)
    ASN_MAX_IPS          - Hard cap on expanded IPs per program, safety valve for large ASNs (default: 65536)
    ASN_EXCLUDE_CDN      - Skip naabu -exclude-cdn filtering on ASN-derived IPs (default: true)
    MAX_JOB_RETENTION_DAYS - Auto-delete scan output older than N days (default: 30, 0=disable)
    DRY_RUN              - Skip external tool execution for testing (default: false)


Expected targets layout:
  targets/
    company_1.txt
    company_2.txt

Each file contains root domains / scope entries, one per line:
  example.com
  api.example.net

External tools expected in PATH:
  - subfinder
  - httpx
  - naabu
  - nuclei
  - katana
  - notify
  - asnmap   (ProjectDiscovery — org/domain -> ASN -> CIDR)
  - mapcidr  (ProjectDiscovery — CIDR dedup/merge/expand to individual IPs)

Python stdlib only.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import logging
import logging.handlers
import re
import shutil
import sqlite3
import shlex
import subprocess
import sys
import threading
import time
import argparse
import urllib.parse
import urllib.request
import urllib.error
import ssl
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Optional, Iterator


# -----------------------------
# Config
# -----------------------------

@dataclass
class Config:
    root_dir: Path
    
    @property
    def targets_dir(self) -> Path:
        return self.root_dir / "targets"
        
    @property
    def db_path(self) -> Path:
        return self.root_dir / "recon.db"
        
    @property
    def workdir(self) -> Path:
        return self.root_dir / "work"
        
    @property
    def log_file(self) -> Path:
        return self.root_dir / "logs" / "recon_watch.log"
        
    notify_bin: str = "notify"
    notify_id: str = ""
    notify_step_by_step: bool = False
    subfinder_bin: str = "subfinder"
    httpx_bin: str = "httpx"
    naabu_bin: str = "naabu"
    nuclei_bin: str = "nuclei"
    katana_bin: str = "katana"
    asnmap_bin: str = "asnmap"
    mapcidr_bin: str = "mapcidr"
    nuclei_enabled: bool = True
    nuclei_severities: str = "medium,high,critical"
    subfinder_timeout: int = 3600
    httpx_timeout: int = 1800
    naabu_timeout: int = 3600
    naabu_nmap_cli: bool = False
    nuclei_timeout: int = 3600
    katana_enabled: bool = True
    katana_timeout: int = 3600
    katana_depth: int = 3
    katana_headless: bool = False
    katana_crawl_js: bool = True
    katana_jsluice: bool = False
    katana_field_scope: str = "rdn"
    katana_custom_scope: str = ""
    asn_enabled: bool = True
    asn_timeout: int = 900
    mapcidr_timeout: int = 300
    asn_alive_timeout: int = 1800
    asn_max_ips: int = 65536
    asn_exclude_cdn: bool = True
    subfinder_provider_config: str = ""
    subfinder_args: str = ""
    httpx_args: str = ""
    naabu_args: str = ""
    nuclei_args: str = ""
    katana_args: str = ""
    asnmap_args: str = ""
    notify_args: str = ""
    js_monitor_enabled: bool = True
    js_monitor_threads: int = 15
    js_monitor_timeout: int = 30
    js_monitor_tool_timeout: int = 900
    js_monitor_recursion_depth: int = 3
    js_monitor_deep: bool = False
    js_monitor_patterns_file: str = ""
    js_monitor_allow_external: bool = False
    max_job_retention_days: int = 30
    dry_run: bool = False


# -----------------------------
# Logging
# -----------------------------

def setup_logging(log_file: Path) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.handlers.RotatingFileHandler(
                log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8",
            ),
        ],
    )


# -----------------------------
# SQLite schema
# -----------------------------

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    scope_file TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    scope_hash TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_scanned_at TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS scope_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    root_domain TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(program_id, root_domain),
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    alive INTEGER NOT NULL DEFAULT 0,
    http_url TEXT,
    http_status INTEGER,
    http_title TEXT,
    http_tech TEXT,
    screenshot_path TEXT,
    last_httpx_at TEXT,
    last_naabu_at TEXT,
    last_nuclei_at TEXT,
    notes TEXT,
    UNIQUE(program_id, host),
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS httpx_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    url TEXT,
    status_code INTEGER,
    title TEXT,
    tech TEXT,
    webserver TEXT,
    host_ip TEXT,
    cname TEXT,
    port INTEGER,
    scheme TEXT,
    content_type TEXT,
    method TEXT,
    path TEXT,
    time TEXT,
    a TEXT,
    aaaa TEXT,
    cdn_name TEXT,
    cdn_type TEXT,
    resolvers TEXT,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    host TEXT,
    ip TEXT,
    open_ports TEXT NOT NULL,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nuclei_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    url TEXT,
    scanned_at TEXT NOT NULL,
    severity TEXT,
    template_id TEXT,
    name TEXT,
    matched_at TEXT,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS katana_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    urls TEXT NOT NULL,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS js_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    source_url TEXT,
    current_hash TEXT,
    content_length INTEGER,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_changed_at TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
    UNIQUE(program_id, url)
);

CREATE TABLE IF NOT EXISTS js_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    js_file_id INTEGER,
    source_url TEXT,
    source_type TEXT NOT NULL DEFAULT 'javascript',
    category TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
    FOREIGN KEY(js_file_id) REFERENCES js_files(id) ON DELETE SET NULL,
    UNIQUE(program_id, source_type, category, value)
);

CREATE TABLE IF NOT EXISTS js_scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    program_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    seed_pages INTEGER NOT NULL DEFAULT 0,
    direct_js_urls INTEGER NOT NULL DEFAULT 0,
    html_pages_scanned INTEGER NOT NULL DEFAULT 0,
    js_files_found INTEGER NOT NULL DEFAULT 0,
    js_files_scanned INTEGER NOT NULL DEFAULT 0,
    js_files_changed INTEGER NOT NULL DEFAULT 0,
    findings_total INTEGER NOT NULL DEFAULT 0,
    findings_new INTEGER NOT NULL DEFAULT 0,
    findings_removed INTEGER NOT NULL DEFAULT 0,
    critical_new INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'ok',
    error TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE SET NULL,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asn_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    asn TEXT NOT NULL,
    org TEXT,
    cidr TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    UNIQUE(program_id, cidr),
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asn_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    cidr TEXT,
    asn TEXT,
    alive INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_checked_at TEXT,
    UNIQUE(program_id, ip),
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS asn_httpx_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER,
    url TEXT,
    status_code INTEGER,
    title TEXT,
    scanned_at TEXT NOT NULL,
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    discovered INTEGER NOT NULL DEFAULT 0,
    new_subdomains INTEGER NOT NULL DEFAULT 0,
    live_subdomains INTEGER NOT NULL DEFAULT 0,
    nuclei_findings INTEGER NOT NULL DEFAULT 0,
    katana_urls INTEGER NOT NULL DEFAULT 0,
    js_files_found INTEGER NOT NULL DEFAULT 0,
    js_files_changed INTEGER NOT NULL DEFAULT 0,
    js_findings_total INTEGER NOT NULL DEFAULT 0,
    js_findings_new INTEGER NOT NULL DEFAULT 0,
    js_findings_removed INTEGER NOT NULL DEFAULT 0,
    js_findings_critical INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scope_program ON scope_domains(program_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_program ON subdomains(program_id);
CREATE INDEX IF NOT EXISTS idx_httpx_program ON httpx_results(program_id);
CREATE INDEX IF NOT EXISTS idx_ports_program ON ports(program_id);
CREATE INDEX IF NOT EXISTS idx_nuclei_program ON nuclei_findings(program_id);
CREATE INDEX IF NOT EXISTS idx_katana_program ON katana_results(program_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nuclei_unique ON nuclei_findings(program_id, subdomain, template_id, url);
CREATE INDEX IF NOT EXISTS idx_js_files_program ON js_files(program_id);
CREATE INDEX IF NOT EXISTS idx_js_files_active ON js_files(program_id, is_active);
CREATE INDEX IF NOT EXISTS idx_js_findings_program ON js_findings(program_id);
CREATE INDEX IF NOT EXISTS idx_js_findings_active ON js_findings(program_id, is_active);
CREATE INDEX IF NOT EXISTS idx_js_scan_history_program ON js_scan_history(program_id);
CREATE INDEX IF NOT EXISTS idx_asn_ranges_program ON asn_ranges(program_id);
CREATE INDEX IF NOT EXISTS idx_asn_ips_program ON asn_ips(program_id);
CREATE INDEX IF NOT EXISTS idx_asn_httpx_program ON asn_httpx_results(program_id);
"""


CURRENT_SCHEMA_VERSION = 6


def run_migrations(conn: sqlite3.Connection) -> None:
    """Run incremental schema migrations based on schema_version table."""
    cur = conn.cursor()
    row = cur.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
    current = row["version"] if row else 0

    if current < 1:
        cur.execute(
            "INSERT INTO schema_version (version, updated_at) VALUES (?, ?)",
            (CURRENT_SCHEMA_VERSION, utc_now()),
        )
    else:
        if current < 3:
            # v3: add katana_urls column to runs table
            try:
                cur.execute("ALTER TABLE runs ADD COLUMN katana_urls INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError:
                pass  # column already exists
        if current < 4:
            # v4: asn_ranges / asn_ips tables created via CREATE TABLE IF NOT EXISTS above.
            # Nothing to backfill; version bump only.
            pass
        if current < 5:
            # v5: JavaScript monitoring tables are created by SCHEMA above; existing
            # databases only need the new run counters added defensively.
            for column in (
                "js_files_found INTEGER NOT NULL DEFAULT 0",
                "js_files_changed INTEGER NOT NULL DEFAULT 0",
                "js_findings_total INTEGER NOT NULL DEFAULT 0",
                "js_findings_new INTEGER NOT NULL DEFAULT 0",
                "js_findings_removed INTEGER NOT NULL DEFAULT 0",
                "js_findings_critical INTEGER NOT NULL DEFAULT 0",
            ):
                try:
                    cur.execute(f"ALTER TABLE runs ADD COLUMN {column}")
                except sqlite3.OperationalError:
                    pass
        if current < 6:
            # v6: Remove duplicate rows from js_findings keeping the lowest id per unique key.
            try:
                cur.execute("""
                    DELETE FROM js_findings
                    WHERE id NOT IN (
                        SELECT MIN(id)
                        FROM js_findings
                        GROUP BY program_id, source_type, category, value
                    )
                """)
            except sqlite3.OperationalError:
                pass
        if current < CURRENT_SCHEMA_VERSION:
            cur.execute(
                "UPDATE schema_version SET version=?, updated_at=?",
                (CURRENT_SCHEMA_VERSION, utc_now()),
            )

    conn.commit()


def connect_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    run_migrations(conn)
    return conn


# -----------------------------
# Helpers
# -----------------------------

def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def safe_name(value: str) -> str:
    out = []
    for ch in value:
        if ch.isalnum() or ch in ("-", "_", "."):
            out.append(ch)
        else:
            out.append("_")
    return "".join(out).strip("_")[:180] or "item"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s.rstrip("."))
    return lines


def run_cmd(cmd: list[str], timeout: int, cwd: Optional[Path] = None, log_prefix: str = "") -> subprocess.CompletedProcess[str]:
    prefix = f"{log_prefix} " if log_prefix else ""
    logging.info("%sRunning: %s", prefix, " ".join(cmd))
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            text=True,
            encoding="utf-8",
            errors="ignore",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        logging.error("Timeout: Command '%s' timed out after %s seconds", " ".join(cmd), timeout)
        out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout.decode('utf-8', errors='ignore') if exc.stdout else "")
        err = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr.decode('utf-8', errors='ignore') if exc.stderr else "")
        return subprocess.CompletedProcess(args=cmd, returncode=124, stdout=out, stderr=err)
    except Exception as exc:
        logging.error("Error executing command '%s': %s", " ".join(cmd), exc)
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr=str(exc))


def first_value(d: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _katana_endpoint(obj: dict[str, Any]) -> str:
    """Extract the endpoint URL from a katana JSONL object."""
    req = obj.get("request")
    if isinstance(req, dict):
        ep = req.get("endpoint") or req.get("url") or ""
        if ep:
            return str(ep).strip()
    return str(first_value(obj, ["endpoint", "url", "input"], "")).strip()


def as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def ensure_utf8_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, ensure_ascii=False)
    except Exception:
        return str(v)


def normalize_url(host: str, url: Optional[str]) -> str:
    if url and isinstance(url, str) and url.startswith(("http://", "https://")):
        return url
    return f"https://{host}"


def host_from_url(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


# -----------------------------
# JavaScript monitor
# -----------------------------

JS_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

# Hard cap on response body size to prevent OOM on unexpectedly large responses
MAX_JS_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB

JS_SKIP_DOMAINS = {
    "www.googletagmanager.com",
    "www.google-analytics.com",
    "connect.facebook.net",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "cdn.skypack.dev",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "cdn.shopify.com",
    "hcaptcha.com",
    "challenges.cloudflare.com",
    "static.cloudflareinsights.com",
}

JS_CRITICAL_CATEGORIES = {
    "api_key",
    "aws_key",
    "aws_secret",
    "google_api_key",
    "credential",
    "jwt",
}

PATTERN_PATHS = re.compile(
    r'''(?:"|'|`|\()(/(?:[a-zA-Z0-9_\-./~@:{}]+/?)*[a-zA-Z0-9_\-./~@:{}]*)["'`\)]?'''
)
PATTERN_URLS = re.compile(r'''https?://[^\s"'`<>\)\]\},]+''')
PATTERN_QUERY_PARAMS = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_]*)=")
PATTERN_FEATURE_FLAGS = re.compile(
    r'''(?:"|'|`)((?:feature[_\s-]?flag|feature[_\s-]?toggle|enable[_\s-]?|'''
    r'''disable[_\s-]?|is[_\s-]?enabled|use[_\s-]?new|show[_\s-]?|hide[_\s-]?|'''
    r'''experiment|ab[_\s-]?test|rollout|beta[_\s-]?|new[_\s-]?ui|'''
    r'''can[_\s-]?|should[_\s-]?|has[_\s-]?)[a-zA-Z0-9_\-]*)["'`\)]?\s*[:=]''',
    re.IGNORECASE,
)
PATTERN_API_KEY_CONTEXT = re.compile(
    r'''(?i)(?:api[_\s-]?key|apikey|access[_\s-]?key|secret[_\s-]?key|'''
    r'''private[_\s-]?key|auth[_\s-]?token|bearer|session[_\s-]?token|'''
    r'''client[_\s-]?secret|app[_\s-]?secret|signing[_\s-]?key|'''
    r'''encryption[_\s-]?key|webhook[_\s-]?secret|publishable[_\s-]?key)'''
    r'''[\s"':=]+(["'`])([a-zA-Z0-9_\-+/=.]{16,})\1'''
)
PATTERN_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
PATTERN_AWS_SECRET = re.compile(
    r'''(?:aws[_\s-]?secret|secret[_\s-]?access[_\s-]?key)[\s"':=]+(["'`])([A-Za-z0-9/+=]{40})\1''',
    re.IGNORECASE,
)
PATTERN_GOOGLE_KEY = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
PATTERN_GENERIC_TOKEN = re.compile(
    r'''["'`](eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})["'`]'''
)
PATTERN_CREDENTIALS = re.compile(
    r'''(?i)(?:password|passwd|pwd|credential|secret|token)\s*[:=]\s*["'`]([^"'\s]{4,})["'`]'''
)
PATTERN_INTERNAL_IPS = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)
PATTERN_COMMENTS = re.compile(r"/\*[\s\S]*?\*/|//.*?$", re.MULTILINE)
PATTERN_FETCH_ENDPOINT = re.compile(
    r'''(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch|XMLHttpRequest|\.ajax)\s*\(\s*["'`]([^"'`]+)["'`]''',
    re.IGNORECASE,
)
PATTERN_GRAPHQL = re.compile(r'''["'`](/graphql|/api/graphql|/gql|/query)["'`]''', re.IGNORECASE)
PATTERN_WEBSOCKET = re.compile(r'''(?:new\s+WebSocket\s*\(\s*["'`])?(wss?://[^"'`\s<>)]+)''', re.IGNORECASE)
PATTERN_DYNAMIC_IMPORT = re.compile(r'''import\s*\(\s*["'`]([^"'`]+\.js(?:\?[^"'`]*)?)["'`]\s*\)''')
PATTERN_WEBPACK_CHUNK_MAP = re.compile(r'''["'](\d+)["']\s*:\s*["']([^"']+\.js[^"']*)["']''')
PATTERN_WEBPACK_PUBLIC_PATH = re.compile(r'''__webpack_require__\.p\s*=\s*["']([^"']+)["']''')
PATTERN_JS_REF_IN_JS = re.compile(
    r'''["'`]((?:[./]*)(?:[a-zA-Z0-9_\-./]+/)*[a-zA-Z0-9_\-]+\.js(?:\?[^"'`]*)?)["'`]'''
)
PATTERN_NEXTJS_CHUNK = re.compile(r'''["_'](/?_next/static/(?:chunks|css)/[^"']+\.js)["']''')
PATTERN_NUXT_CHUNK = re.compile(r'''["_'](/?_nuxt/[^"']+\.js)["']''')
PATTERN_VITE_CHUNK = re.compile(r'''["_'](/?assets/[^"']+\.js)["']''')
PATTERN_SERVICE_WORKER = re.compile(
    r'''(?:navigator\.serviceWorker\.register|registerServiceWorker)\s*\(\s*["'`]([^"'`]+)["'`]'''
)

_js_thread_local = threading.local()


class ScriptDiscoveringHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.script_srcs: list[str] = []
        self.modulepreload_hrefs: list[str] = []
        self.inline_scripts: list[str] = []
        self._capture_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_map = {k.lower(): v or "" for k, v in attrs}
        tag = tag.lower()
        if tag == "script":
            src = attr_map.get("src", "").strip()
            if src:
                self.script_srcs.append(html.unescape(src))
            else:
                self._capture_script = True
        elif tag == "link":
            rel = attr_map.get("rel", "").lower()
            href = attr_map.get("href", "").strip()
            if href and "modulepreload" in rel and is_probable_js_url(href):
                self.modulepreload_hrefs.append(html.unescape(href))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._capture_script = False

    def handle_data(self, data: str) -> None:
        if self._capture_script and data:
            self.inline_scripts.append(data)


def dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def normalize_monitor_url(url: str, base: str = "") -> str:
    url = html.unescape(str(url or "").strip())
    if not url:
        return ""
    if base:
        url = urllib.parse.urljoin(base, url)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return ""
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def is_probable_js_url(url: str) -> bool:
    path = urllib.parse.urlparse(url).path.lower()
    return path.endswith(".js") or ".js/" in path or ".js;" in path or ".js?" in url.lower()


def url_in_scope(url: str, roots: list[str], allow_external: bool) -> bool:
    if allow_external:
        return True
    host = host_from_url(url).lower().rstrip(".")
    if not host:
        return False
    return any(host == root.lower().rstrip(".") or host.endswith("." + root.lower().rstrip(".")) for root in roots)


def filter_monitor_urls(urls: list[str], roots: list[str], allow_external: bool, js_only: bool = False) -> list[str]:
    filtered: list[str] = []
    for url in urls:
        normalized = normalize_monitor_url(url)
        if not normalized:
            continue
        host = host_from_url(normalized).lower().rstrip(".")
        if host in JS_SKIP_DOMAINS and not allow_external:
            continue
        if js_only and not is_probable_js_url(normalized):
            continue
        if url_in_scope(normalized, roots, allow_external):
            filtered.append(normalized)
    return dedupe_strings(filtered)


def get_js_opener() -> urllib.request.OpenerDirector:
    opener = getattr(_js_thread_local, "opener", None)
    if opener is None:
        # Skip SSL verification — many bug bounty targets have self-signed,
        # expired, or misconfigured certificates that would cause every fetch
        # to fail silently.  This mirrors what httpx/katana do by default.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        https_handler = urllib.request.HTTPSHandler(context=ctx)
        http_handler = urllib.request.HTTPHandler()
        opener = urllib.request.build_opener(http_handler, https_handler)
        _js_thread_local.opener = opener
    return opener


def _read_with_deadline(resp: Any, max_bytes: int, deadline: float) -> bytes:
    """Read response body in chunks, aborting if deadline or size limit is exceeded."""
    chunks: list[bytes] = []
    total = 0
    while True:
        if time.time() > deadline:
            raise TimeoutError("Total transfer deadline exceeded")
        remaining_bytes = max_bytes - total
        if remaining_bytes <= 0:
            break
        chunk = resp.read(min(65536, remaining_bytes))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def fetch_monitor_url(cfg: Config, url: str, js_file: bool = False) -> Optional[str]:
    """Fetch a single URL with per-request hard deadline, size cap, and content-type validation."""
    max_retries = 2
    timeout_per_request = cfg.js_monitor_timeout
    for attempt in range(max_retries):
        resp = None
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": JS_USER_AGENT,
                    "Accept": "*/*" if js_file else "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )
            # Hard deadline: socket timeout + total transfer time capped
            deadline = time.time() + timeout_per_request
            resp = get_js_opener().open(req, timeout=min(timeout_per_request, 15))

            # Check for cross-domain redirects (urllib follows redirects silently)
            final_url = resp.url if hasattr(resp, "url") else url
            if final_url:
                orig_host = host_from_url(url).lower().rstrip(".")
                final_host = host_from_url(final_url).lower().rstrip(".")
                if orig_host and final_host and orig_host != final_host:
                    # Redirected to a completely different domain — likely a login/SSO page
                    if not final_host.endswith("." + orig_host) and not orig_host.endswith("." + final_host):
                        logging.info("JS fetch cross-domain redirect %s → %s, skipping", url, final_url)
                        return None

            # Content-type validation for JS files: reject HTML error pages
            if js_file:
                content_type = (resp.headers.get("Content-Type") or "").lower()
                if "text/html" in content_type or "application/xhtml" in content_type:
                    logging.info("JS fetch got HTML response for JS URL (likely error/redirect page): %s", url)
                    return None

            # Read body with hard deadline and size cap
            raw = _read_with_deadline(resp, MAX_JS_RESPONSE_BYTES, deadline)
            charset = resp.headers.get_content_charset() or "utf-8"
            try:
                return raw.decode(charset, errors="replace")
            except LookupError:
                return raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            logging.info("JS fetch HTTP %d: %s", exc.code, url)
            return None
        except TimeoutError as exc:
            if attempt < max_retries - 1:
                time.sleep(1 + attempt)
                continue
            logging.info("JS fetch timeout: %s — %s", url, exc)
            return None
        except (urllib.error.URLError, ValueError, OSError) as exc:
            if attempt < max_retries - 1:
                time.sleep(1 + attempt)
                continue
            logging.info("JS fetch failed: %s — %s", url, exc)
            return None
        finally:
            if resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass
    return None


def iter_fetch_monitor(cfg: Config, urls: list[str], js_file: bool = False) -> Iterator[tuple[str, Optional[str]]]:
    """Yields (url, response_body) one by one as they complete.
    
    Abandons running threads and prevents memory leaks if timeout occurs.
    """
    if not urls:
        return
    max_time_seconds = cfg.js_monitor_tool_timeout
    workers = max(1, min(cfg.js_monitor_threads, len(urls)))
    batch_start = time.time()
    timed_out = False
    pool = ThreadPoolExecutor(max_workers=workers)
    futures = {}
    try:
        for url in urls:
            futures[pool.submit(fetch_monitor_url, cfg, url, js_file)] = url
            
        for future in as_completed(futures, timeout=max(1, max_time_seconds - int(time.time() - batch_start))):
            url = futures.pop(future)  # Remove reference immediately to free memory
            try:
                res = future.result(timeout=5)
            except Exception:
                res = None
            yield url, res

            if time.time() - batch_start > max_time_seconds:
                timed_out = True
                break
    except TimeoutError:
        timed_out = True
    finally:
        if timed_out:
            pending = len(futures)
            logging.warning(
                "JS monitor batch timeout (%ds): abandoned %d remaining URLs",
                max_time_seconds, pending,
            )
        # Cancel queued (not yet started) futures
        for f in futures:
            f.cancel()
        # Shut down without waiting for stuck threads (daemon-like behavior)
        pool.shutdown(wait=False)


def discover_js_html(html_text: str, base: str) -> list[str]:
    parser = ScriptDiscoveringHTMLParser()
    try:
        parser.feed(html_text)
    except Exception:
        pass

    found: list[str] = []
    for src in parser.script_srcs + parser.modulepreload_hrefs:
        found.append(normalize_monitor_url(src, base))
    for script in parser.inline_scripts:
        for match in re.finditer(r'''["']([^"']*\.js(?:\?[^"']*)?)["']''', script):
            found.append(normalize_monitor_url(match.group(1), base))
    for match in re.finditer(r'''["']((?:/[^"']*/)*[^"']*\.js(?:\?[^"']*)?)["']''', html_text):
        found.append(normalize_monitor_url(match.group(1), base))
    return filter_monitor_urls(found, [], True, js_only=True)


def get_webpack_public_path(content: str) -> str:
    match = PATTERN_WEBPACK_PUBLIC_PATH.search(content)
    return match.group(1) if match else ""


def discover_js_from_js(content: str, base: str, public_path: str = "") -> list[str]:
    found: list[str] = []

    def resolve(raw: str) -> str:
        raw = raw.strip()
        if public_path and not raw.startswith(("/", "http://", "https://")):
            raw = public_path + raw
        return normalize_monitor_url(raw, base)

    for match in PATTERN_DYNAMIC_IMPORT.finditer(content):
        found.append(resolve(match.group(1)))
    for match in PATTERN_WEBPACK_CHUNK_MAP.finditer(content):
        found.append(resolve(match.group(2)))
    for pattern in (PATTERN_NEXTJS_CHUNK, PATTERN_NUXT_CHUNK, PATTERN_VITE_CHUNK):
        for match in pattern.finditer(content):
            found.append(resolve(match.group(1)))
    for match in PATTERN_JS_REF_IN_JS.finditer(content):
        raw = match.group(1)
        if "/" in raw or raw.startswith("."):
            found.append(resolve(raw))
    for match in PATTERN_SERVICE_WORKER.finditer(content):
        found.append(resolve(match.group(1)))

    return filter_monitor_urls(found, [], True, js_only=True)


def fetch_sitemap_routes(cfg: Config, base: str, roots: list[str]) -> list[str]:
    parsed = urllib.parse.urlparse(base)
    if not parsed.scheme or not parsed.netloc:
        return []
    sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
    body = fetch_monitor_url(cfg, sitemap_url, js_file=False)
    if not body:
        return []

    routes: list[str] = []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []

    namespaces = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    sitemap_locs = [loc.text.strip() for loc in root.findall(".//sm:sitemap/sm:loc", namespaces) if loc.text]
    page_locs = [loc.text.strip() for loc in root.findall(".//sm:loc", namespaces) if loc.text]
    routes.extend(page_locs)

    for nested in sitemap_locs[:5]:
        nested_body = fetch_monitor_url(cfg, nested, js_file=False)
        if not nested_body:
            continue
        try:
            nested_root = ET.fromstring(nested_body)
        except ET.ParseError:
            continue
        routes.extend([loc.text.strip() for loc in nested_root.findall(".//sm:loc", namespaces) if loc.text])

    return filter_monitor_urls(routes, roots, cfg.js_monitor_allow_external, js_only=False)


def context_slice(content: str, pos: int, width: int = 80) -> str:
    start = max(0, pos - width)
    end = min(len(content), pos + width)
    return " ".join(content[start:end].replace("\r", " ").replace("\n", " ").split())


def load_js_custom_patterns(config_path: str) -> list[dict[str, Any]]:
    if not config_path:
        return []
    path = Path(config_path).expanduser()
    if not path.exists():
        logging.warning("JS monitor custom regex config not found: %s", path)
        return []

    try:
        config = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError) as exc:
        logging.warning("Failed to load JS custom regex config %s: %s", path, exc)
        return []

    entries: list[dict[str, Any]] = []
    if isinstance(config, dict):
        entries = config.get("custom_patterns", [])
    elif isinstance(config, list):
        entries = config
    else:
        logging.warning(
            "JS monitor custom regex config has unexpected top-level type: %s", type(config).__name__
        )
        return []

    patterns: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).strip()
        regex = str(entry.get("regex", "")).strip()
        if not name or not regex:
            logging.warning("Skipping JS custom regex entry missing name/regex")
            continue
        flags = re.IGNORECASE if entry.get("ignore_case", False) else 0
        try:
            compiled = re.compile(regex, flags)
        except re.error as exc:
            logging.warning("Skipping invalid JS custom regex %s: %s", name, exc)
            continue
        patterns.append(
            {
                "name": name,
                "regex": compiled,
                "group_index": int(entry.get("group_index", 0)),
            }
        )
    return patterns


def extract_monitor_findings(content: str, custom_patterns: list[dict[str, Any]], include_comments: bool = True) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(category: str, value: str, context: str = "") -> None:
        value = ensure_utf8_text(value).strip()
        if not value:
            return
        key = (category, value)
        if key in seen:
            return
        seen.add(key)
        findings.append({"category": category, "value": value, "context": ensure_utf8_text(context)})

    for match in PATTERN_PATHS.finditer(content):
        path = match.group(1)
        if len(path) < 3 or path.startswith(("//", "/*")):
            continue
        if re.match(r"^/[a-z]", path, re.IGNORECASE) or "/api/" in path.lower():
            add("path", path, context_slice(content, match.start()))

    for match in PATTERN_URLS.finditer(content):
        url = match.group(0).rstrip(".,;)")
        try:
            parsed = urllib.parse.urlparse(url)
        except ValueError:
            continue
        if parsed.netloc in JS_SKIP_DOMAINS and parsed.path in ("", "/"):
            continue
        add("url", url, context_slice(content, match.start()))
        for param_match in PATTERN_QUERY_PARAMS.finditer(url):
            add("parameter", param_match.group(1), f"From URL: {url[:120]}")

    for match in PATTERN_FEATURE_FLAGS.finditer(content):
        add("feature_flag", match.group(1), context_slice(content, match.start()))
    for match in PATTERN_API_KEY_CONTEXT.finditer(content):
        add("api_key", match.group(2), f"Context: {match.group(0)[:120]}")
    for match in PATTERN_AWS_KEY.finditer(content):
        add("aws_key", match.group(0), context_slice(content, match.start()))
    for match in PATTERN_AWS_SECRET.finditer(content):
        add("aws_secret", match.group(2), f"Context: {match.group(0)[:120]}")
    for match in PATTERN_GOOGLE_KEY.finditer(content):
        add("google_api_key", match.group(0), context_slice(content, match.start()))
    for match in PATTERN_GENERIC_TOKEN.finditer(content):
        token = match.group(1)
        add("jwt", token[:80] + ("..." if len(token) > 80 else ""), context_slice(content, match.start()))
    for match in PATTERN_CREDENTIALS.finditer(content):
        value = match.group(1)
        if value.lower() in ("null", "undefined", "true", "false", "''", '""', "``") or len(value) < 3:
            continue
        add("credential", value, context_slice(content, match.start()))
    for match in PATTERN_INTERNAL_IPS.finditer(content):
        add("internal_ip", match.group(0), context_slice(content, match.start()))

    if include_comments:
        for match in PATTERN_COMMENTS.finditer(content):
            comment = match.group(0).strip()
            lowered = comment.lower()
            if any(
                keyword in lowered
                for keyword in (
                    "todo",
                    "fixme",
                    "hack",
                    "xxx",
                    "bug",
                    "vuln",
                    "security",
                    "temp",
                    "temporary",
                    "remove",
                    "deprecated",
                    "backdoor",
                    "debug",
                    "testing",
                    "staging",
                    "internal",
                    "secret",
                    "hardcoded",
                )
            ):
                add("comment", comment[:200] + ("..." if len(comment) > 200 else ""), "")

    for match in PATTERN_FETCH_ENDPOINT.finditer(content):
        add("fetch_endpoint", match.group(1), context_slice(content, match.start()))
    for match in PATTERN_GRAPHQL.finditer(content):
        add("graphql_endpoint", match.group(1), context_slice(content, match.start()))
    for match in PATTERN_WEBSOCKET.finditer(content):
        add("websocket", match.group(1), context_slice(content, match.start()))

    for pattern in custom_patterns:
        for match in pattern["regex"].finditer(content):
            group_index = int(pattern.get("group_index", 0))
            if group_index == 0:
                value = match.group(0)
            else:
                try:
                    value = match.group(group_index)
                except IndexError:
                    value = match.group(0)
            add(pattern["name"], value, context_slice(content, match.start()))

    return findings


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def mask_sensitive_value(value: str) -> str:
    value = ensure_utf8_text(value)
    if len(value) <= 10:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def _write_js_monitor_output_files(
    job_dir: Path,
    result: dict[str, Any],
    seed_pages: list[str],
    direct_js: list[str],
) -> None:
    """Write JS monitor output files. Called from finally block to guarantee output."""
    try:
        (job_dir / "js_monitor_seed_pages.txt").write_text("\n".join(seed_pages) + "\n", encoding="utf-8")
        (job_dir / "js_monitor_direct_js.txt").write_text("\n".join(direct_js) + "\n", encoding="utf-8")
        (job_dir / "js_monitor_js_files.txt").write_text(
            "\n".join(result.get("discovered_js_urls", [])) + "\n", encoding="utf-8"
        )
        (job_dir / "js_monitor_failed_js.txt").write_text(
            "\n".join(result.get("failed_js_urls", [])) + "\n", encoding="utf-8"
        )
        (job_dir / "js_monitor_failed_pages.txt").write_text(
            "\n".join(result.get("failed_page_urls", [])) + "\n", encoding="utf-8"
        )
        write_jsonl(job_dir / "js_monitor_findings.jsonl", result.get("findings", []))
    except Exception:
        logging.exception("JS Monitor: failed to write output files")


def run_js_monitor_scan(
    cfg: Config,
    page_urls: list[str],
    direct_js_urls: list[str],
    roots: list[str],
    job_dir: Path,
) -> dict[str, Any]:
    started_at = utc_now()
    result: dict[str, Any] = {
        "started_at": started_at,
        "status": "ok",
        "error": "",
        "seed_page_urls": [],
        "direct_js_urls": [],
        "html_pages_scanned": 0,
        "discovered_js_urls": [],
        "fetched_js_urls": [],
        "failed_page_urls": [],
        "failed_js_urls": [],
        "js_hashes": {},
        "js_meta": {},
        "findings": [],
        "custom_patterns_loaded": 0,
    }

    if not cfg.js_monitor_enabled:
        result["status"] = "disabled"
        return result
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping JS monitor")
        result["status"] = "dry_run"
        return result

    # These are populated early so the finally block can always write them
    seed_pages: list[str] = []
    direct_js: list[str] = []

    try:
        custom_patterns = load_js_custom_patterns(cfg.js_monitor_patterns_file)
        result["custom_patterns_loaded"] = len(custom_patterns)

        seed_pages = filter_monitor_urls(page_urls, roots, cfg.js_monitor_allow_external, js_only=False)
        seed_pages = [url for url in seed_pages if not is_probable_js_url(url)]
        direct_js = filter_monitor_urls(direct_js_urls, roots, cfg.js_monitor_allow_external, js_only=True)
        result["seed_page_urls"] = seed_pages
        result["direct_js_urls"] = direct_js

        discovered_js: set[str] = set(direct_js)
        js_sources: dict[str, str] = {url: "katana" for url in direct_js}

        if seed_pages:
            logging.info("JS Monitor: Fetching %d seed HTML pages...", len(seed_pages))
            for page_url, body in iter_fetch_monitor(cfg, seed_pages, js_file=False):
                if not body:
                    result["failed_page_urls"].append(page_url)
                    continue
                result["html_pages_scanned"] += 1
                html_findings = extract_monitor_findings(body, custom_patterns, include_comments=False)
                for finding in html_findings:
                    finding.update({"source_url": page_url, "source_type": "html"})
                result["findings"].extend(html_findings)

                for js_url in filter_monitor_urls(discover_js_html(body, page_url), roots, cfg.js_monitor_allow_external, js_only=True):
                    discovered_js.add(js_url)
                    js_sources.setdefault(js_url, page_url)

        if cfg.js_monitor_deep and seed_pages:
            origins = dedupe_strings(
                [
                    f"{urllib.parse.urlparse(url).scheme}://{urllib.parse.urlparse(url).netloc}"
                    for url in seed_pages
                    if urllib.parse.urlparse(url).scheme and urllib.parse.urlparse(url).netloc
                ]
            )
            sitemap_pages: list[str] = []
            for origin in origins:
                sitemap_pages.extend(fetch_sitemap_routes(cfg, origin, roots)[:20])
            sitemap_pages = [url for url in dedupe_strings(sitemap_pages) if url not in set(seed_pages)]
            if sitemap_pages:
                logging.info("JS Monitor: Fetching %d deep HTML sitemap pages...", len(sitemap_pages))
                for page_url, body in iter_fetch_monitor(cfg, sitemap_pages, js_file=False):
                    if not body:
                        result["failed_page_urls"].append(page_url)
                        continue
                    result["html_pages_scanned"] += 1
                    html_findings = extract_monitor_findings(body, custom_patterns, include_comments=False)
                    for finding in html_findings:
                        finding.update({"source_url": page_url, "source_type": "html"})
                    result["findings"].extend(html_findings)
                    for js_url in filter_monitor_urls(discover_js_html(body, page_url), roots, cfg.js_monitor_allow_external, js_only=True):
                        discovered_js.add(js_url)
                        js_sources.setdefault(js_url, page_url)

        attempted_js: set[str] = set()
        fetched_js: set[str] = set()
        public_path = ""
        max_depth = max(1, cfg.js_monitor_recursion_depth)

        for _depth in range(max_depth):
            to_fetch = sorted(discovered_js - attempted_js)
            if not to_fetch:
                break
            logging.info("JS Monitor: Fetching %d JS files at depth %d/%d...", len(to_fetch), _depth + 1, max_depth)
            for js_url, body in iter_fetch_monitor(cfg, to_fetch, js_file=True):
                attempted_js.add(js_url)
                if body is None:
                    result["failed_js_urls"].append(js_url)
                    continue
                fetched_js.add(js_url)
                content_bytes = body.encode("utf-8", errors="replace")
                result["js_hashes"][js_url] = hashlib.sha256(content_bytes).hexdigest()
                result["js_meta"][js_url] = {
                    "content_length": len(content_bytes),
                    "source_url": js_sources.get(js_url, ""),
                }
                js_findings = extract_monitor_findings(body, custom_patterns, include_comments=True)
                for finding in js_findings:
                    finding.update({"source_url": js_url, "source_type": "javascript"})
                result["findings"].extend(js_findings)

                if not public_path:
                    public_path = get_webpack_public_path(body)
                for child_js in filter_monitor_urls(discover_js_from_js(body, js_url, public_path), roots, cfg.js_monitor_allow_external, js_only=True):
                    discovered_js.add(child_js)
                    js_sources.setdefault(child_js, js_url)

        # Deduplicate findings: keep first occurrence per (source_type, category, value)
        seen_findings: set[tuple[str, str, str]] = set()
        deduped_findings: list[dict[str, str]] = []
        for finding in result["findings"]:
            key = (finding.get("source_type", "javascript"), finding.get("category", ""), finding.get("value", ""))
            if key not in seen_findings:
                seen_findings.add(key)
                deduped_findings.append(finding)
        result["findings"] = deduped_findings

        result["discovered_js_urls"] = sorted(discovered_js)
        result["fetched_js_urls"] = sorted(fetched_js)

        logging.info(
            "JS Monitor: completed — discovered=%d fetched=%d failed_js=%d failed_pages=%d findings=%d",
            len(discovered_js),
            len(fetched_js),
            len(result["failed_js_urls"]),
            len(result["failed_page_urls"]),
            len(result["findings"]),
        )

    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        logging.exception("JS Monitor: scan failed with exception")

    finally:
        # Always write output files, even on partial failure or crash
        _write_js_monitor_output_files(job_dir, result, seed_pages, direct_js)

    return result


def get_known_live_urls(conn: sqlite3.Connection, program_id: int) -> list[str]:
    rows = conn.execute(
        """
        SELECT DISTINCT http_url
        FROM subdomains
        WHERE program_id=? AND alive=1 AND http_url IS NOT NULL AND http_url <> ''
        ORDER BY http_url
        """,
        (program_id,),
    ).fetchall()
    return [str(row["http_url"]).strip() for row in rows if str(row["http_url"]).strip()]


def upsert_js_file(
    cur: sqlite3.Cursor,
    program_id: int,
    url: str,
    content_hash: str,
    source_url: str,
    content_length: int,
    ts: str,
) -> tuple[int, str]:
    row = cur.execute(
        "SELECT id, current_hash, is_active FROM js_files WHERE program_id=? AND url=?",
        (program_id, url),
    ).fetchone()
    if row is None:
        cur.execute(
            """
            INSERT INTO js_files (
                program_id, url, source_url, current_hash, content_length,
                first_seen_at, last_seen_at, last_changed_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (program_id, url, source_url, content_hash, content_length, ts, ts, ts),
        )
        return int(cur.lastrowid), "new"

    status = "unchanged"
    if row["current_hash"] != content_hash:
        status = "changed"
    elif int(row["is_active"]) == 0:
        status = "reactivated"

    cur.execute(
        """
        UPDATE js_files
        SET source_url=?, current_hash=?, content_length=?, last_seen_at=?,
            last_changed_at=CASE WHEN current_hash <> ? THEN ? ELSE last_changed_at END,
            is_active=1
        WHERE id=?
        """,
        (source_url, content_hash, content_length, ts, content_hash, ts, int(row["id"])),
    )
    return int(row["id"]), status


def deactivate_missing_js_files(cur: sqlite3.Cursor, program_id: int, seen_urls: set[str], ts: str) -> list[dict[str, Any]]:
    rows = cur.execute(
        "SELECT id, url, current_hash FROM js_files WHERE program_id=? AND is_active=1",
        (program_id,),
    ).fetchall()
    removed = [dict(row) for row in rows if row["url"] not in seen_urls]
    for row in removed:
        cur.execute("UPDATE js_files SET is_active=0, last_seen_at=? WHERE id=?", (ts, row["id"]))
    return removed


def upsert_js_finding(
    cur: sqlite3.Cursor,
    program_id: int,
    js_file_id: Optional[int],
    source_url: str,
    source_type: str,
    category: str,
    value: str,
    context: str,
    ts: str,
) -> str:
    row = cur.execute(
        """
        SELECT id, is_active
        FROM js_findings
        WHERE program_id=? AND source_type=? AND category=? AND value=?
        """,
        (program_id, source_type, category, value),
    ).fetchone()
    if row is None:
        cur.execute(
            """
            INSERT INTO js_findings (
                program_id, js_file_id, source_url, source_type, category, value,
                context, first_seen_at, last_seen_at, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (program_id, js_file_id, source_url, source_type, category, value, context, ts, ts),
        )
        return "new"

    status = "reactivated" if int(row["is_active"]) == 0 else "existing"
    cur.execute(
        """
        UPDATE js_findings
        SET js_file_id=?, source_url=?, context=?, last_seen_at=?, is_active=1
        WHERE id=?
        """,
        (js_file_id, source_url, context, ts, int(row["id"])),
    )
    return status


def deactivate_missing_js_findings(
    cur: sqlite3.Cursor,
    program_id: int,
    seen_keys: set[tuple[str, str, str]],
    ts: str,
) -> list[dict[str, Any]]:
    rows = cur.execute(
        """
        SELECT id, source_url, source_type, category, value, context
        FROM js_findings
        WHERE program_id=? AND is_active=1
        """,
        (program_id,),
    ).fetchall()
    removed = [
        dict(row)
        for row in rows
        if (row["source_type"], row["category"], row["value"]) not in seen_keys
    ]
    for row in removed:
        cur.execute("UPDATE js_findings SET is_active=0, last_seen_at=? WHERE id=?", (ts, row["id"]))
    return removed


def store_js_monitor_results(
    conn: sqlite3.Connection,
    program_id: int,
    run_id: int,
    result: dict[str, Any],
    job_dir: Path,
) -> dict[str, Any]:
    ts = utc_now()
    cur = conn.cursor()

    changed_files: list[dict[str, Any]] = []
    js_file_ids: dict[str, int] = {}
    for js_url, content_hash in result.get("js_hashes", {}).items():
        meta = result.get("js_meta", {}).get(js_url, {})
        js_file_id, status = upsert_js_file(
            cur,
            program_id,
            js_url,
            content_hash,
            ensure_utf8_text(meta.get("source_url", "")),
            int(meta.get("content_length", 0) or 0),
            ts,
        )
        js_file_ids[js_url] = js_file_id
        if status in ("new", "changed", "reactivated"):
            changed_files.append(
                {
                    "url": js_url,
                    "status": status,
                    "hash": content_hash,
                    "source_url": ensure_utf8_text(meta.get("source_url", "")),
                }
            )

    removed_js = deactivate_missing_js_files(
        cur,
        program_id,
        set(result.get("discovered_js_urls", [])),
        ts,
    ) if result.get("discovered_js_urls") else []

    new_findings: list[dict[str, Any]] = []
    seen_finding_keys: set[tuple[str, str, str]] = set()
    for finding in result.get("findings", []):
        source_type = ensure_utf8_text(finding.get("source_type", "javascript")) or "javascript"
        source_url = ensure_utf8_text(finding.get("source_url", ""))
        category = ensure_utf8_text(finding.get("category", ""))
        value = ensure_utf8_text(finding.get("value", ""))
        context = ensure_utf8_text(finding.get("context", ""))
        if not category or not value:
            continue
        js_file_id = js_file_ids.get(source_url) if source_type == "javascript" else None
        status = upsert_js_finding(
            cur,
            program_id,
            js_file_id,
            source_url,
            source_type,
            category,
            value,
            context,
            ts,
        )
        seen_finding_keys.add((source_type, category, value))
        if status in ("new", "reactivated"):
            new_findings.append(
                {
                    "source_url": source_url,
                    "source_type": source_type,
                    "category": category,
                    "value": value,
                    "context": context,
                    "status": status,
                }
            )

    skipped_deactivation = bool(result.get("failed_js_urls") or result.get("failed_page_urls"))
    removed_findings = []
    if not skipped_deactivation:
        removed_findings = deactivate_missing_js_findings(cur, program_id, seen_finding_keys, ts)

    critical_new = [finding for finding in new_findings if finding["category"] in JS_CRITICAL_CATEGORIES]

    cur.execute(
        """
        INSERT INTO js_scan_history (
            run_id, program_id, started_at, completed_at, seed_pages, direct_js_urls,
            html_pages_scanned, js_files_found, js_files_scanned, js_files_changed,
            findings_total, findings_new, findings_removed, critical_new, status, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            program_id,
            result.get("started_at") or ts,
            ts,
            len(result.get("seed_page_urls", [])),
            len(result.get("direct_js_urls", [])),
            int(result.get("html_pages_scanned", 0) or 0),
            len(result.get("discovered_js_urls", [])),
            len(result.get("fetched_js_urls", [])),
            len(changed_files),
            len(result.get("findings", [])),
            len(new_findings),
            len(removed_findings),
            len(critical_new),
            result.get("status", "ok"),
            result.get("error", ""),
        ),
    )
    cur.execute(
        """
        UPDATE runs
        SET js_files_found=?, js_files_changed=?, js_findings_total=?,
            js_findings_new=?, js_findings_removed=?, js_findings_critical=?
        WHERE id=?
        """,
        (
            len(result.get("discovered_js_urls", [])),
            len(changed_files),
            len(result.get("findings", [])),
            len(new_findings),
            len(removed_findings),
            len(critical_new),
            run_id,
        ),
    )
    conn.commit()

    result["changed_files"] = changed_files
    result["removed_js"] = removed_js
    result["new_findings"] = new_findings
    result["removed_findings"] = removed_findings
    result["critical_new_findings"] = critical_new
    result["skipped_deactivation"] = skipped_deactivation

    write_jsonl(job_dir / "js_monitor_changed_files.jsonl", changed_files)
    write_jsonl(job_dir / "js_monitor_new_findings.jsonl", new_findings)
    write_jsonl(job_dir / "js_monitor_removed_findings.jsonl", removed_findings)

    return result


# -----------------------------
# Telegram
# -----------------------------

def send_notify(cfg: Config, message: str) -> None:
    """Send a notification using ProjectDiscovery's notify tool via stdin."""
    if not message.strip():
        return

    cmd = [cfg.notify_bin, "-silent", "-bulk"]
    if cfg.notify_id:
        cmd.extend(["-id", cfg.notify_id])
    if cfg.notify_args:
        cmd.extend(shlex.split(cfg.notify_args))

    try:
        subprocess.run(
            cmd,
            input=message,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=60,
            check=False,
            capture_output=True
        )
    except Exception as exc:
        logging.error("Notify tool error: %s", exc)


# -----------------------------
# Program sync
# -----------------------------

def sync_targets_dir(conn: sqlite3.Connection, targets_dir: Path) -> list[sqlite3.Row]:
    """
    Each *.txt file becomes one program.
    Filename stem is the program name.
    File contents are scope roots.
    Only updates scope_domains when the scope file content has changed.
    """
    now = utc_now()
    cur = conn.cursor()
    programs: list[sqlite3.Row] = []

    target_files = sorted([p for p in targets_dir.iterdir() if p.is_file() and not p.name.startswith(".")])
    active_program_names = set()

    for scope_file in target_files:
        program_name = scope_file.stem
        active_program_names.add(program_name)
        roots = read_lines(scope_file)
        scope_hash = hashlib.sha256("\n".join(sorted(set(roots))).encode("utf-8")).hexdigest()

        row = cur.execute("SELECT * FROM programs WHERE name=?", (program_name,)).fetchone()
        if row is None:
            cur.execute(
                """
                INSERT INTO programs (name, scope_file, enabled, scope_hash, created_at, updated_at, notes)
                VALUES (?, ?, 1, ?, ?, ?, ?)
                """,
                (
                    program_name,
                    str(scope_file),
                    scope_hash,
                    now,
                    now,
                    "auto-imported from targets directory",
                ),
            )
            program_id = cur.lastrowid

            for root in sorted(set(roots)):
                cur.execute(
                    """
                    INSERT OR IGNORE INTO scope_domains (program_id, root_domain, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (program_id, root, now),
                )
        else:
            program_id = row["id"]
            old_hash = row["scope_hash"]

            if old_hash != scope_hash:
                logging.info("[%s] scope changed, updating domains", program_name)
                cur.execute(
                    """
                    UPDATE programs
                    SET scope_file=?, enabled=1, scope_hash=?, updated_at=?
                    WHERE id=?
                    """,
                    (str(scope_file), scope_hash, now, program_id),
                )
                cur.execute("DELETE FROM scope_domains WHERE program_id=?", (program_id,))

                for root in sorted(set(roots)):
                    cur.execute(
                        """
                        INSERT OR IGNORE INTO scope_domains (program_id, root_domain, created_at)
                        VALUES (?, ?, ?)
                        """,
                        (program_id, root, now),
                    )
            else:
                cur.execute(
                    "UPDATE programs SET scope_file=?, enabled=1, updated_at=? WHERE id=?",
                    (str(scope_file), now, program_id),
                )

    # Disable programs that no longer have a target file
    all_db_programs = cur.execute("SELECT id, name, enabled FROM programs").fetchall()
    for db_prog in all_db_programs:
        if db_prog["name"] not in active_program_names and db_prog["enabled"] == 1:
            logging.info("[%s] target file removed, disabling program", db_prog["name"])
            cur.execute("UPDATE programs SET enabled=0, updated_at=? WHERE id=?", (now, db_prog["id"]))
    conn.commit()

    for row in cur.execute("SELECT * FROM programs WHERE enabled=1 ORDER BY name"):
        programs.append(row)
    return programs


def scope_roots_for_program(conn: sqlite3.Connection, program_id: int) -> list[str]:
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT root_domain FROM scope_domains WHERE program_id=? ORDER BY root_domain ASC",
        (program_id,),
    ).fetchall()
    return [r["root_domain"] for r in rows]


# -----------------------------
# Discovery
# -----------------------------

def run_subfinder(cfg: Config, domains: list[str], job_dir: Path, log_prefix: str = "") -> set[str]:
    if not domains:
        return set()
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping subfinder for %d domains", len(domains))
        return set()

    roots_file = job_dir / "roots.txt"
    roots_file.write_text("\n".join(domains) + "\n", encoding="utf-8")
    out_file = job_dir / "subfinder.txt"

    cmd = [
        cfg.subfinder_bin,
        "-dL", str(roots_file),
        "-silent",
        "-o", str(out_file),
    ]
    if cfg.subfinder_args:
        cmd.extend(shlex.split(cfg.subfinder_args))
    if cfg.subfinder_provider_config:
        cmd.extend(["-pc", cfg.subfinder_provider_config])

    run_cmd(cmd, timeout=cfg.subfinder_timeout, log_prefix=log_prefix)
    
    if not out_file.exists():
        return set()

    subs = set()
    for line in out_file.read_text(encoding="utf-8").splitlines():
        s = line.strip().rstrip(".")
        if s:
            subs.add(s)
    return subs


def update_subdomains(conn: sqlite3.Connection, program_id: int, discovered: set[str]) -> tuple[list[str], list[str]]:
    now = utc_now()
    cur = conn.cursor()

    existing = {
        row["host"]
        for row in cur.execute("SELECT host FROM subdomains WHERE program_id=?", (program_id,))
    }
    new_hosts = sorted(discovered - existing)
    seen_hosts = sorted(discovered & existing)

    for host in seen_hosts:
        cur.execute(
            "UPDATE subdomains SET last_seen=? WHERE program_id=? AND host=?",
            (now, program_id, host),
        )

    for host in new_hosts:
        cur.execute(
            """
            INSERT INTO subdomains (
                program_id, host, first_seen, last_seen, alive, notes
            ) VALUES (?, ?, ?, ?, 0, ?)
            """,
            (program_id, host, now, now, "newly discovered"),
        )

    conn.commit()
    return new_hosts, seen_hosts


# -----------------------------
# httpx
# -----------------------------

def run_httpx(cfg: Config, hosts: list[str], job_dir: Path, log_prefix: str = "") -> tuple[list[dict[str, Any]], list[str]]:
    if not hosts:
        return [], []
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping httpx for %d hosts", len(hosts))
        return [], []

    host_file = job_dir / "httpx_hosts.txt"
    host_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    out_file = job_dir / "httpx.jsonl"
    cmd = [
        cfg.httpx_bin,
        "-l", str(host_file),
        "-json",
        "-sc",
        "-title",
        "-td",
        "-server",
        "-ip",
        "-cname",
        "-no-color",
        "-silent",
        "-o", str(out_file),
    ]
    if cfg.httpx_args:
        cmd.extend(shlex.split(cfg.httpx_args))

    run_cmd(cmd, timeout=cfg.httpx_timeout, log_prefix=log_prefix)

    _seen_lines: set[str] = set()
    def iter_lines():
        if out_file.exists():
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    yield line

    results: list[dict[str, Any]] = []
    live_hosts: list[str] = []

    for line in iter_lines():
        line = line.strip()
        if not line or line in _seen_lines:
            continue
        _seen_lines.add(line)
        try:
            obj = json.loads(line)
        except Exception:
            continue

        host = str(first_value(obj, ["host", "input", "hostname", "domain"], "")).strip().rstrip(".")
        url = str(first_value(obj, ["url", "final_url", "matched_url"], "")).strip()
        status_code = first_value(obj, ["status_code", "status"], None)
        title = first_value(obj, ["title"], "")
        tech = first_value(obj, ["tech", "technologies", "technology"], [])
        server = first_value(obj, ["server", "webserver"], "")
        ip = first_value(obj, ["ip"], "")
        cname = first_value(obj, ["cname"], "")

        if not host and url:
            host = host_from_url(url)

        if not url and host:
            url = normalize_url(host, url)

        alive = False
        try:
            alive = int(status_code) > 0
        except Exception:
            alive = bool(url)

        screenshot_path = None
        # Best effort: if httpx exposes any screenshot-like field, save it.
        for key, value in obj.items():
            if "screenshot" in key.lower():
                if isinstance(value, str) and value.strip() and host:
                    # If value is a file path, copy it; if base64, attempt to decode.
                    candidate = Path(value)
                    if candidate.exists():
                        ss_dir = ensure_dir(job_dir / "screenshots")
                        dest = ss_dir / f"{safe_name(host)}.png"
                        shutil.copy2(candidate, dest)
                        screenshot_path = str(dest)
                        break

        if alive and host:
            live_hosts.append(host)

        results.append(
            {
                "subdomain": host,
                "url": url,
                "status_code": int(status_code) if isinstance(status_code, (int, float, str)) and str(status_code).isdigit() else None,
                "title": ensure_utf8_text(title),
                "tech": json.dumps(as_list(tech), ensure_ascii=False),
                "webserver": ensure_utf8_text(first_value(obj, ["webserver", "server"], "")),
                "host_ip": ensure_utf8_text(first_value(obj, ["host_ip", "ip"], "")),
                "cname": ensure_utf8_text(cname),
                "screenshot_path": screenshot_path,
                "alive": 1 if alive else 0,
                
                "port": first_value(obj, ["port"], None),
                "scheme": str(first_value(obj, ["scheme"], "")).strip(),
                "content_type": str(first_value(obj, ["content_type"], "")).strip(),
                "method": str(first_value(obj, ["method"], "")).strip(),
                "path": str(first_value(obj, ["path"], "")).strip(),
                "time": str(first_value(obj, ["time"], "")).strip(),
                "a": json.dumps(as_list(obj.get("a", [])), ensure_ascii=False),
                "aaaa": json.dumps(as_list(obj.get("aaaa", [])), ensure_ascii=False),
                "cdn_name": str(first_value(obj, ["cdn_name"], "")).strip(),
                "cdn_type": str(first_value(obj, ["cdn_type"], "")).strip(),
                "resolvers": json.dumps(as_list(obj.get("resolvers", [])), ensure_ascii=False),
            }
        )

    deduped_live = []
    seen = set()
    for h in live_hosts:
        if h not in seen:
            seen.add(h)
            deduped_live.append(h)

    return results, deduped_live


def store_httpx(conn: sqlite3.Connection, program_id: int, results: list[dict[str, Any]], job_dir: Path) -> None:
    now = utc_now()
    cur = conn.cursor()

    for r in results:
        sub = r["subdomain"]
        if not sub:
            continue

        cur.execute(
            """
            INSERT INTO httpx_results (
                program_id, subdomain, scanned_at, url, status_code, title, tech,
                webserver, host_ip, cname, port, scheme, content_type, method, path, time,
                a, aaaa, cdn_name, cdn_type, resolvers
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_id,
                sub,
                now,
                r["url"],
                r["status_code"],
                r["title"],
                r["tech"],
                r["webserver"],
                r["host_ip"],
                r["cname"],
                int(r["port"]) if r["port"] and str(r["port"]).isdigit() else None,
                r["scheme"],
                r["content_type"],
                r["method"],
                r["path"],
                r["time"],
                r["a"],
                r["aaaa"],
                r["cdn_name"],
                r["cdn_type"],
                r["resolvers"],
            ),
        )

        cur.execute(
            """
            UPDATE subdomains
            SET alive=?, http_url=?, http_status=?, http_title=?, http_tech=?, screenshot_path=?, last_httpx_at=?
            WHERE program_id=? AND host=?
            """,
            (
                r["alive"],
                r["url"],
                r["status_code"],
                r["title"],
                r["tech"],
                r["screenshot_path"],
                now,
                program_id,
                sub,
            ),
        )

    conn.commit()


# -----------------------------
# naabu
# -----------------------------

def run_naabu(cfg: Config, hosts: list[str], job_dir: Path, alive_check: bool = False, log_prefix: str = "") -> list[dict[str, Any]]:
    if not hosts:
        return []
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping naabu for %d hosts", len(hosts))
        return []

    file_name = "asn_ips_for_alive_check.txt" if alive_check else "naabu_hosts.txt"
    out_name = "asn_alive.jsonl" if alive_check else "naabu.jsonl"
    
    host_file = job_dir / file_name
    host_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

    out_file = job_dir / out_name
    cmd = [
        cfg.naabu_bin,
        "-list", str(host_file),
    ]
    if alive_check:
        cmd.extend(["-top-ports", "100"])
    
    cmd.extend([
        "-Pn",
        "-verify",
        "-json",
        "-silent",
        "-o", str(out_file),
    ])
    if cfg.naabu_args:
        cmd.extend(shlex.split(cfg.naabu_args))

    run_cmd(cmd, timeout=cfg.naabu_timeout, log_prefix=log_prefix)

    _seen_lines: set[str] = set()
    def iter_lines():
        if out_file.exists():
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    yield line

    results: list[dict[str, Any]] = []
    for line in iter_lines():
        line = line.strip()
        if not line or line in _seen_lines:
            continue
        _seen_lines.add(line)
        try:
            obj = json.loads(line)
        except Exception:
            continue

        host = str(first_value(obj, ["host", "hostname", "input"], "")).strip().rstrip(".")
        ip = str(first_value(obj, ["ip", "ip_address"], "")).strip()
        port = first_value(obj, ["port"], None)
        protocol = str(first_value(obj, ["protocol", "proto"], "")).strip()
        service = str(first_value(obj, ["service", "name"], "")).strip()
        version = str(first_value(obj, ["version", "product", "service_version", "banner", "cpe"], "")).strip()

        results.append(
            {
                "subdomain": host,
                "host": host,
                "ip": ip,
                "port": int(port) if isinstance(port, (int, float, str)) and str(port).isdigit() else None,
                "protocol": protocol,
                "service": service,
                "version": version,
                "raw_json": json.dumps(obj, ensure_ascii=False),
            }
        )

    return results


def store_ports(conn: sqlite3.Connection, program_id: int, port_results: list[dict[str, Any]]) -> None:
    now = utc_now()
    cur = conn.cursor()

    grouped = {}
    for r in port_results:
        sub = r.get("subdomain", "")
        if not sub:
            continue
        if sub not in grouped:
            grouped[sub] = {"host": r.get("host", ""), "ip": r.get("ip", ""), "ports": []}
        
        grouped[sub]["ports"].append({
            "port": r.get("port"),
            "protocol": r.get("protocol"),
            "service": r.get("service"),
            "version": r.get("version"),
        })

    for sub, data in grouped.items():
        unique_ports = {}
        for p in data["ports"]:
            key = (p["port"], p["protocol"])
            if key not in unique_ports:
                unique_ports[key] = p
            else:
                if not unique_ports[key].get("version") and p.get("version"):
                    unique_ports[key] = p
                    
        sorted_ports = sorted(unique_ports.values(), key=lambda x: int(x["port"]) if x["port"] and str(x["port"]).isdigit() else 0)

        cur.execute(
            """
            INSERT INTO ports (
                program_id, subdomain, scanned_at, host, ip, open_ports
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                program_id,
                sub,
                now,
                data["host"],
                data["ip"],
                json.dumps(sorted_ports, ensure_ascii=False),
            ),
        )

        cur.execute(
            "UPDATE subdomains SET last_naabu_at=? WHERE program_id=? AND host=?",
            (now, program_id, sub),
        )

    conn.commit()


# -----------------------------
# ASN -> CIDR -> IP -> alive recon
# -----------------------------

def run_asnmap(cfg: Config, domains: list[str], job_dir: Path, log_prefix: str = "") -> list[dict[str, Any]]:
    if not domains:
        return []
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping asnmap for %d domains", len(domains))
        return []

    dom_file = job_dir / "asn_domains.txt"
    dom_file.write_text("\n".join(domains) + "\n", encoding="utf-8")
    out_file = job_dir / "asnmap.jsonl"
    cmd = [
        cfg.asnmap_bin,
        "-f", str(dom_file),
        "-json",
        "-silent",
        "-o", str(out_file),
    ]
    if cfg.asnmap_args:
        cmd.extend(shlex.split(cfg.asnmap_args))

    run_cmd(cmd, timeout=cfg.asn_timeout, log_prefix=log_prefix)

    _seen_lines: set[str] = set()
    def iter_lines():
        if out_file.exists():
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    yield line

    ranges: dict[str, dict[str, Any]] = {}
    for line in iter_lines():
        line = line.strip()
        if not line or line in _seen_lines:
            continue
        _seen_lines.add(line)

        try:
            obj = json.loads(line)
        except Exception:
            if "/" in line:
                ranges[line] = {"asn": "", "org": "", "cidr": line}
            continue

        asn = str(first_value(obj, ["as_number", "asn"], "")).strip()
        org = str(first_value(obj, ["as_name", "org", "as_org"], "")).strip()
        cidr_field = first_value(obj, ["as_range", "range", "cidr", "cidrs"], None)

        for cidr in as_list(cidr_field):
            cidr = str(cidr).strip()
            if cidr and "/" in cidr:
                ranges[cidr] = {"asn": asn, "org": org, "cidr": cidr}

    return list(ranges.values())


def store_asn_ranges(conn: sqlite3.Connection, program_id: int, ranges: list[dict[str, Any]]) -> None:
    if not ranges:
        return
    now = utc_now()
    cur = conn.cursor()
    for r in ranges:
        cur.execute(
            """
            INSERT INTO asn_ranges (program_id, asn, org, cidr, discovered_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(program_id, cidr) DO UPDATE SET
                asn=excluded.asn,
                org=excluded.org
            """,
            (program_id, r.get("asn", ""), r.get("org", ""), r["cidr"], now),
        )
    conn.commit()


def run_mapcidr_expand(cfg: Config, cidrs: list[str], job_dir: Path, cap: int, log_prefix: str = "") -> list[str]:
    if not cidrs:
        return []
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping mapcidr for %d cidrs", len(cidrs))
        return []

    cidr_file = job_dir / "asn_cidrs.txt"
    cidr_file.write_text("\n".join(cidrs) + "\n", encoding="utf-8")
    
    cmd_count = [cfg.mapcidr_bin, "-cidr", str(cidr_file), "-count", "-silent"]
    proc_count = run_cmd(cmd_count, timeout=300, log_prefix=log_prefix)
    total_ips = 0
    for line in proc_count.stdout.splitlines():
        line = line.strip()
        if line.isdigit():
            total_ips += int(line)
            
    if total_ips > cap:
        logging.warning("mapcidr: Expansion would produce %d IPs (cap is %d). Truncating output.", total_ips, cap)
        out_file = job_dir / "asn_ips.txt"
        cmd_expand = [cfg.mapcidr_bin, "-cidr", str(cidr_file), "-silent", "-o", str(out_file)]
        run_cmd(cmd_expand, timeout=600, log_prefix=log_prefix)
        ips = []
        try:
            with open(out_file, "r", encoding="utf-8") as f:
                for line in f:
                    ips.append(line.strip())
                    if len(ips) >= cap:
                        break
        except FileNotFoundError:
            pass
        return ips
        
    cmd_expand = [cfg.mapcidr_bin, "-cidr", str(cidr_file), "-silent"]
    proc_expand = run_cmd(cmd_expand, timeout=600, log_prefix=log_prefix)
    ips = [ip.strip() for ip in proc_expand.stdout.splitlines() if ip.strip()]
    return ips[:cap]


def store_asn_ips(conn: sqlite3.Connection, program_id: int, ips: list[str]) -> None:
    if not ips:
        return
    now = utc_now()
    cur = conn.cursor()
    for ip in ips:
        cur.execute(
            """
            INSERT INTO asn_ips (program_id, ip, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(program_id, ip) DO UPDATE SET last_seen=excluded.last_seen
            """,
            (program_id, ip, now, now),
        )
    conn.commit()


def run_asn_alive_check(cfg: Config, ips: list[str], job_dir: Path, log_prefix: str = "") -> list[str]:
    if not ips:
        return []
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping ASN alive check for %d IP(s)", len(ips))
        return []

    ip_file = job_dir / "asn_ips_for_alive_check.txt"
    ip_file.write_text("\n".join(ips) + "\n", encoding="utf-8")

    out_file = job_dir / "asn_alive.jsonl"
    cmd = [
        cfg.naabu_bin,
        "-list", str(ip_file),
        "-top-ports", "100",
        "-Pn",
        "-verify",
        "-json",
        "-silent",
        "-o", str(out_file),
    ]
    if cfg.asn_exclude_cdn:
        cmd.append("-exclude-cdn")

    run_cmd(cmd, timeout=cfg.asn_alive_timeout, log_prefix=log_prefix)

    alive: list[str] = []
    seen: set[str] = set()
    if out_file.exists():
        for line in out_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line: continue
            try:
                obj = json.loads(line)
                ip = str(first_value(obj, ["ip", "host"], "")).strip()
                if ip and ip not in seen:
                    seen.add(ip)
                    alive.append(ip)
            except Exception: continue

    return alive


def mark_asn_ips_alive(conn: sqlite3.Connection, program_id: int, alive_ips: list[str]) -> None:
    if not alive_ips:
        return
    now = utc_now()
    cur = conn.cursor()
    cur.executemany(
        "UPDATE asn_ips SET alive=1, last_checked_at=? WHERE program_id=? AND ip=?",
        [(now, program_id, ip) for ip in alive_ips],
    )
    conn.commit()


def store_asn_httpx(conn: sqlite3.Connection, program_id: int, results: list[dict[str, Any]]) -> None:
    """Store httpx results from ASN pipeline into asn_httpx_results table."""
    if not results:
        return
    now = utc_now()
    cur = conn.cursor()
    for r in results:
        cur.execute(
            """
            INSERT INTO asn_httpx_results (
                program_id, ip, port, url, status_code, title, scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_id,
                r.get("ip", ""),
                r.get("port"),
                r.get("url", ""),
                r.get("status_code"),
                r.get("title", ""),
                now,
            ),
        )
    conn.commit()


def run_asn_httpx(
    cfg: Config,
    port_results: list[dict[str, Any]],
    job_dir: Path,
    log_prefix: str = "",
) -> list[dict[str, Any]]:
    """Run httpx on alive IPs with open ports to get status codes and titles.
    Generates targets as IP:PORT for each unique IP:port combination.
    """
    if not port_results:
        return []
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping ASN httpx for %d port results", len(port_results))
        return []

    # Build unique IP:PORT targets
    seen_targets: set[tuple[str, int]] = set()
    targets: list[str] = []
    for p in port_results:
        host = (p.get("host") or p.get("ip") or p.get("subdomain", "")).strip()
        port = p.get("port")
        if not host or not port:
            continue
        key = (host, int(port))
        if key in seen_targets:
            continue
        seen_targets.add(key)
        targets.append(f"{host}:{port}")

    if not targets:
        return []

    target_file = job_dir / "asn_httpx_targets.txt"
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

    out_file = job_dir / "asn_httpx.jsonl"
    cmd = [
        cfg.httpx_bin,
        "-l", str(target_file),
        "-json",
        "-sc",
        "-title",
        "-no-color",
        "-silent",
        "-o", str(out_file),
    ]
    if cfg.httpx_args:
        cmd.extend(shlex.split(cfg.httpx_args))

    run_cmd(cmd, timeout=cfg.httpx_timeout, log_prefix=log_prefix)

    results: list[dict[str, Any]] = []
    _seen_lines: set[str] = set()
    if out_file.exists():
        for line in out_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line in _seen_lines:
                continue
            _seen_lines.add(line)
            try:
                obj = json.loads(line)
            except Exception:
                continue

            host = str(first_value(obj, ["host", "input", "ip"], "")).strip().rstrip(".")
            url = str(first_value(obj, ["url", "final_url"], "")).strip()
            status_code = first_value(obj, ["status_code", "status"], None)
            title = ensure_utf8_text(first_value(obj, ["title"], ""))
            port_val = first_value(obj, ["port"], None)

            # Extract IP from host (might be IP:port format)
            ip = host.split(":")[0] if ":" in host else host

            results.append({
                "ip": ip,
                "port": int(port_val) if port_val and str(port_val).isdigit() else None,
                "url": url,
                "status_code": int(status_code) if isinstance(status_code, (int, float, str)) and str(status_code).isdigit() else None,
                "title": title,
            })

    return results


def run_asn_recon(cfg: Config, roots: list[str], job_dir: Path) -> tuple[list[dict[str, Any]], list[str], list[str], list[dict[str, Any]]]:
    """ASN recon: asnmap → mapcidr → naabu (alive IPs + open ports).
    Returns (asn_ranges, all_ips, alive_ips, port_results).
    """
    if not cfg.asn_enabled:
        return [], [], [], []

    asn_ranges = run_asnmap(cfg, roots, job_dir, log_prefix="[ASN Pipeline]")
    if not asn_ranges:
        return [], [], [], []

    cidrs = [r["cidr"] for r in asn_ranges]
    ips = run_mapcidr_expand(cfg, cidrs, job_dir, cap=cfg.asn_max_ips, log_prefix="[ASN Pipeline]")
    if not ips:
        return asn_ranges, [], [], []

    # Use naabu with alive_check=True to get both alive IPs and open ports
    port_results = run_naabu(cfg, ips, job_dir, alive_check=True, log_prefix="[ASN Pipeline]")

    # Extract unique alive IPs from port results
    alive_set: set[str] = set()
    for p in port_results:
        host = p.get("host") or p.get("ip") or p.get("subdomain", "")
        if host:
            alive_set.add(host.strip())
    alive_ips = sorted(alive_set)

    return asn_ranges, ips, alive_ips, port_results


# -----------------------------
# nuclei
# -----------------------------

def run_nuclei(cfg: Config, urls: list[str], job_dir: Path, log_prefix: str = "") -> list[dict[str, Any]]:
    if not urls:
        return []
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping nuclei for %d urls", len(urls))
        return []

    url_file = job_dir / "nuclei_urls.txt"
    url_file.write_text("\n".join(urls) + "\n", encoding="utf-8")

    out_file = job_dir / "nuclei.jsonl"
    cmd = [
        cfg.nuclei_bin,
        "-l", str(url_file),
        "-severity", cfg.nuclei_severities,
        "-jsonl",
        "-silent",
        "-ni",
        "-o", str(out_file),
    ]
    if cfg.nuclei_args:
        cmd.extend(shlex.split(cfg.nuclei_args))

    run_cmd(cmd, timeout=cfg.nuclei_timeout, log_prefix=log_prefix)

    _seen_lines: set[str] = set()
    def iter_lines():
        if out_file.exists():
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    yield line

    findings: list[dict[str, Any]] = []
    for line in iter_lines():
        line = line.strip()
        if not line or line in _seen_lines:
            continue
        _seen_lines.add(line)
        try:
            obj = json.loads(line)
        except Exception:
            continue

        info = obj.get("info", {})
        url = str(first_value(obj, ["matched-at", "matched_at", "url", "host"], "")).strip()
        severity = str(first_value(obj, ["severity"], "") or info.get("severity", "")).strip()
        template_id = str(first_value(obj, ["template-id", "template_id"], "") or obj.get("id", "")).strip()
        name = str(first_value(obj, ["name"], "") or info.get("name", "")).strip()
        matched_at = str(first_value(obj, ["matched-at", "matched_at"], "")).strip()

        subdomain = host_from_url(url) if url else ""
        findings.append(
            {
                "subdomain": subdomain,
                "url": url,
                "severity": severity,
                "template_id": template_id,
                "name": name,
                "matched_at": matched_at,
                "raw_json": json.dumps(obj, ensure_ascii=False),
            }
        )

    return findings


def store_nuclei(conn: sqlite3.Connection, program_id: int, findings: list[dict[str, Any]]) -> None:
    now = utc_now()
    cur = conn.cursor()

    for f in findings:
        if not f["subdomain"]:
            continue

        cur.execute(
            """
            INSERT OR IGNORE INTO nuclei_findings (
                program_id, subdomain, url, scanned_at, severity, template_id, name, matched_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_id,
                f["subdomain"],
                f["url"],
                now,
                f["severity"],
                f["template_id"],
                f["name"],
                f["matched_at"],
            ),
        )

        cur.execute(
            "UPDATE subdomains SET last_nuclei_at=? WHERE program_id=? AND host=?",
            (now, program_id, f["subdomain"]),
        )

    conn.commit()


# -----------------------------
# katana
# -----------------------------

def run_katana(cfg: Config, urls: list[str], job_dir: Path, roots: list[str], log_prefix: str = "") -> list[str]:
    if not urls:
        return []
    if cfg.dry_run:
        logging.info("[DRY_RUN] Skipping katana for %d urls", len(urls))
        return []

    url_file = job_dir / "katana_input_urls.txt"
    url_file.write_text("\n".join(urls) + "\n", encoding="utf-8")

    out_file = job_dir / "katana.jsonl"
    cmd = [
        cfg.katana_bin,
        "-list", str(url_file),
        "-depth", str(cfg.katana_depth),
        "-jsonl",
        "-silent",
        "-no-color",
        "-o", str(out_file),
    ]

    if cfg.katana_field_scope:
        cmd.extend(["-fs", cfg.katana_field_scope])

    if cfg.katana_custom_scope:
        cmd.extend(["-cs", cfg.katana_custom_scope])

    if cfg.katana_crawl_js:
        cmd.extend(["-jc"])

    if cfg.katana_jsluice:
        cmd.extend(["-jsluice"])

    if cfg.katana_headless:
        cmd.extend(["-headless"])
        
    if cfg.katana_args:
        cmd.extend(shlex.split(cfg.katana_args))

    proc = run_cmd(cmd, timeout=cfg.katana_timeout, log_prefix=log_prefix)

    _seen_lines: set[str] = set()
    def iter_lines():
        if out_file.exists():
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    yield line
        if proc.stdout:
            for line in proc.stdout.splitlines():
                yield line

    discovered_urls: list[str] = []
    seen: set[str] = set()
    for line in iter_lines():
        line = line.strip()
        if not line or line in _seen_lines:
            continue
        _seen_lines.add(line)
        try:
            obj = json.loads(line)
        except Exception:
            # Plain URL line (non-JSON mode fallback)
            if line.startswith("http"):
                host = host_from_url(line)
                is_valid = any(host == r or host.endswith("." + r) for r in roots) if roots else True
                if is_valid and line not in seen:
                    seen.add(line)
                    discovered_urls.append(line)
            continue

        endpoint = _katana_endpoint(obj)
        if endpoint.startswith("http"):
            host = host_from_url(endpoint)
            is_valid = any(host == r or host.endswith("." + r) for r in roots) if roots else True
            if is_valid and endpoint not in seen:
                seen.add(endpoint)
                discovered_urls.append(endpoint)

    return discovered_urls


def parse_katana_results(job_dir: Path, roots: list[str] = None) -> list[dict[str, Any]]:
    """Parse katana JSONL output into structured dicts for DB storage."""
    out_file = job_dir / "katana.jsonl"
    if not out_file.exists():
        return []

    results: list[dict[str, Any]] = []
    with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue

            endpoint = _katana_endpoint(obj)
            host = host_from_url(endpoint)
            is_valid = any(host == r or host.endswith("." + r) for r in roots) if roots else True
            if not is_valid:
                continue
            if not endpoint:
                continue

            subdomain = host_from_url(endpoint) if endpoint else ""
            method = str(first_value(obj, ["method"], "")).strip().upper() or "GET"
            status_code = first_value(obj, ["status_code", "status-code"], None)
            source = str(first_value(obj, ["source"], "")).strip()

            results.append(
                {
                    "subdomain": subdomain,
                    "url": endpoint,
                    "method": method,
                    "status_code": int(status_code) if isinstance(status_code, (int, float, str)) and str(status_code).isdigit() else None,
                    "source": source,
                    "raw_json": json.dumps(obj, ensure_ascii=False),
                }
            )

    return results


def store_katana(conn: sqlite3.Connection, program_id: int, katana_results: list[dict[str, Any]]) -> None:
    now = utc_now()
    cur = conn.cursor()

    grouped = {}
    for r in katana_results:
        sub = r.get("subdomain", "")
        if not sub:
            continue
        grouped.setdefault(sub, set()).add(r["url"])

    for sub, urls in grouped.items():
        sorted_urls = sorted(list(urls))
        cur.execute(
            """
            INSERT INTO katana_results (
                program_id, subdomain, scanned_at, urls
            ) VALUES (?, ?, ?, ?)
            """,
            (
                program_id,
                sub,
                now,
                json.dumps(sorted_urls, ensure_ascii=False),
            ),
        )

    conn.commit()


# -----------------------------
# Reporting
# -----------------------------

TELEGRAM_MESSAGE_LIMIT = 3900
SUMMARY_HOST_LIMIT = 20
SUMMARY_LIST_LIMIT = 20


def clean_text(value: Any, max_chars: int = 160) -> str:
    text = ensure_utf8_text(value).replace("\r", " ").replace("\n", " ")
    text = " ".join(text.split())
    if not text:
        return "N/A"
    if len(text) > max_chars:
        return text[: max_chars - 3].rstrip() + "..."
    return text


def md_text(value: Any, max_chars: int = 160) -> str:
    return clean_text(value, max_chars)


def md_code(value: Any, max_chars: int = 160) -> str:
    return f"`{md_text(value, max_chars)}`"


def format_code_list(items: list[str], limit: int = SUMMARY_LIST_LIMIT) -> str:
    shown = [md_code(item, 100) for item in items[:limit]]
    if len(items) > limit:
        shown.append(f"+{len(items) - limit} more")
    return ", ".join(shown) if shown else "none"


def format_tech(tech: Any) -> str:
    if isinstance(tech, str):
        try:
            values = as_list(json.loads(tech))
        except Exception:
            values = [tech]
    else:
        values = as_list(tech)

    cleaned = [clean_text(item, 40) for item in values if clean_text(item, 40) != "N/A"]
    if not cleaned:
        return "none"
    return md_text(", ".join(cleaned[:6]), 180)


def format_port_entry(port: dict[str, Any]) -> str:
    port_value = port.get("port") or "?"
    protocol = clean_text(port.get("protocol"), 20)
    service = clean_text(port.get("service"), 40)
    version = clean_text(port.get("version"), 80)

    endpoint = str(port_value)
    if protocol != "N/A":
        endpoint = f"{endpoint}/{protocol}"

    details = " ".join(part for part in (service, version) if part != "N/A")
    return clean_text(f"{endpoint} {details}".strip(), 120)


def format_ports(ports: list[dict[str, Any]], limit: int = 6) -> str:
    entries: list[str] = []
    seen: set[str] = set()
    for port in ports:
        entry = format_port_entry(port)
        if entry in seen:
            continue
        seen.add(entry)
        entries.append(entry)

    shown = [md_code(entry, 120) for entry in entries[:limit]]
    if len(entries) > limit:
        shown.append(f"+{len(entries) - limit} more")
    return ", ".join(shown) if shown else "none"


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = clean_text(finding.get("severity") or "unknown", 30).lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def format_severity_counts(findings: list[dict[str, Any]]) -> str:
    counts = severity_counts(findings)
    if not counts:
        return "none"

    ordered = ["critical", "high", "medium", "low", "info", "unknown"]
    parts = [f"{sev}: {counts.pop(sev)}" for sev in ordered if sev in counts]
    parts.extend(f"{sev}: {count}" for sev, count in sorted(counts.items()))
    return ", ".join(parts)


def format_js_monitor_counts(js_monitor_result: Optional[dict[str, Any]]) -> str:
    if not js_monitor_result:
        return "disabled"
    status = js_monitor_result.get("status", "ok")
    if status in ("disabled", "dry_run"):
        return status
    return (
        f"{len(js_monitor_result.get('discovered_js_urls', []))} JS file(s), "
        f"{len(js_monitor_result.get('changed_files', []))} changed/new, "
        f"{len(js_monitor_result.get('new_findings', []))} new finding(s), "
        f"{len(js_monitor_result.get('critical_new_findings', []))} critical"
    )


def group_by_subdomain(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        host = str(item.get("subdomain") or "").strip()
        if not host:
            continue
        grouped.setdefault(host, []).append(item)
    return grouped


def build_program_summary_report(
    cfg: Config,
    program_name: str,
    roots: list[str],
    job_dir: Path,
    discovered_count: int,
    new_hosts: list[str],
    seen_hosts: list[str],
    httpx_results: list[dict[str, Any]],
    live_hosts: list[str],
    port_results: list[dict[str, Any]],
    nuclei_findings: list[dict[str, Any]],
    katana_urls_count: int = 0,
    js_monitor_result: Optional[dict[str, Any]] = None,
) -> str:
    httpx_by_host = {str(r.get("subdomain") or ""): r for r in httpx_results}
    ports_by_host = group_by_subdomain(port_results)
    nuclei_by_host = group_by_subdomain(nuclei_findings)
    live_set = set(live_hosts)
    non_live_new_hosts = [host for host in new_hosts if host not in live_set]

    lines = [
        "**Recon Summary**",
        f"Program: {md_code(program_name)}",
        f"Time: {md_text(utc_now(), 40)}",
        f"Scope roots: {len(roots)} ({format_code_list(roots, 8)})",
        "",
        "**Tool summary**",
        f"- Subfinder: {discovered_count} discovered, {len(new_hosts)} new, {len(seen_hosts)} already known",
        f"- HTTPX: {len(httpx_results)} checked, {len(live_hosts)} live",
        f"- Naabu: {len(port_results)} port/service result(s)",
        f"- Katana: {katana_urls_count} crawled URL(s)" + ("" if cfg.katana_enabled else " (disabled)"),
        f"- JS Monitor: {format_js_monitor_counts(js_monitor_result)}",
        f"- Nuclei: {len(nuclei_findings)} finding(s) ({format_severity_counts(nuclei_findings)})" + ("" if cfg.nuclei_enabled else " (disabled)"),
        "",
        "**New subdomains**",
        format_code_list(new_hosts),
    ]

    if live_hosts:
        lines.extend(["", "**Live host details**"])
        for host in live_hosts[:SUMMARY_HOST_LIMIT]:
            httpx_result = httpx_by_host.get(host, {})
            title = httpx_result.get("title") or "N/A"
            status = httpx_result.get("status_code") or "N/A"
            url = httpx_result.get("url") or f"https://{host}"
            tech = format_tech(httpx_result.get("tech"))
            host_ports = ports_by_host.get(host, [])
            host_findings = nuclei_by_host.get(host, [])

            lines.extend(
                [
                    f"- {md_code(host)}",
                    f"  URL: {md_text(url, 220)}",
                    f"  HTTP: {md_text(status, 20)} - {md_text(title, 140)}",
                    f"  Tech: {tech}",
                    f"  Ports: {format_ports(host_ports)}",
                    f"  Nuclei: {format_severity_counts(host_findings)}",
                ]
            )

        if len(live_hosts) > SUMMARY_HOST_LIMIT:
            lines.append(f"- +{len(live_hosts) - SUMMARY_HOST_LIMIT} more live host(s)")
    else:
        lines.extend(["", "**Live host details**", "No live hosts found among new subdomains."])

    if non_live_new_hosts:
        lines.extend(
            [
                "",
                f"**New non-live subdomains** ({len(non_live_new_hosts)})",
                format_code_list(non_live_new_hosts),
            ]
        )

    return "\n".join(lines)


def notify_program_summary(
    cfg: Config,
    program_name: str,
    roots: list[str],
    job_dir: Path,
    discovered_count: int,
    new_hosts: list[str],
    seen_hosts: list[str],
    httpx_results: list[dict[str, Any]],
    live_hosts: list[str],
    port_results: list[dict[str, Any]],
    nuclei_findings: list[dict[str, Any]],
    katana_urls_count: int = 0,
    js_monitor_result: Optional[dict[str, Any]] = None,
) -> None:
    if not cfg.notify_bin:
        return

    report = build_program_summary_report(
        cfg=cfg,
        program_name=program_name,
        roots=roots,
        job_dir=job_dir,
        discovered_count=discovered_count,
        new_hosts=new_hosts,
        seen_hosts=seen_hosts,
        httpx_results=httpx_results,
        live_hosts=live_hosts,
        port_results=port_results,
        nuclei_findings=nuclei_findings,
        katana_urls_count=katana_urls_count,
        js_monitor_result=js_monitor_result,
    )
    try:
        send_notify(cfg, report)
    except Exception as exc:
        logging.error("Notify summary send failed for %s: %s", program_name, exc)


def notify_js_monitor_findings(cfg: Config, program_name: str, result: dict[str, Any]) -> None:
    if not cfg.notify_step_by_step or not cfg.notify_bin:
        return
    if result.get("status") in ("disabled", "dry_run"):
        return

    changed_files = result.get("changed_files", [])
    new_findings = result.get("new_findings", [])
    critical_findings = result.get("critical_new_findings", [])
    removed_findings = result.get("removed_findings", [])
    non_critical_findings = [f for f in new_findings if f not in critical_findings]

    if not changed_files and not new_findings and not removed_findings:
        send_notify(
            cfg,
            f"[{program_name}] **JS monitor finished**: no JS changes or new regex findings.",
        )
        return

    lines = [
        f"[{program_name}] **JS Monitor Report**",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📁 JS files found: {len(result.get('discovered_js_urls', []))}",
        f"🔄 Changed/new JS files: {len(changed_files)}",
        f"🆕 New findings: {len(new_findings)}",
        f"🗑 Removed findings: {len(removed_findings)}",
    ]

    # ── Critical findings first (top priority) ───────────────────────
    if critical_findings:
        lines.extend(["", "🔴 **CRITICAL FINDINGS** 🔴"])
        for finding in critical_findings[:10]:
            value = mask_sensitive_value(ensure_utf8_text(finding.get("value", "")))
            source = md_text(finding.get("source_url", ""), 160)
            lines.append(
                f"  • {md_code(finding.get('category', ''), 30)} {md_text(value, 100)}"
            )
            lines.append(f"    ↳ {source}")
        if len(critical_findings) > 10:
            lines.append(f"  *...and {len(critical_findings) - 10} more critical*")

    # ── Non-critical new findings grouped by category ────────────────
    if non_critical_findings:
        lines.extend(["", "🟡 **New Findings**"])
        # Group by category
        by_category: dict[str, list[dict[str, Any]]] = {}
        for finding in non_critical_findings:
            cat = finding.get("category", "unknown")
            by_category.setdefault(cat, []).append(finding)

        shown = 0
        for cat, findings_list in sorted(by_category.items()):
            if shown >= 15:
                remaining = sum(len(v) for v in by_category.values()) - shown
                if remaining > 0:
                    lines.append(f"  *...and {remaining} more findings*")
                break
            lines.append(f"  **{cat}** ({len(findings_list)})")
            for finding in findings_list[:5]:
                value = ensure_utf8_text(finding.get("value", ""))
                source = md_text(finding.get("source_url", ""), 140)
                lines.append(f"    • {md_text(value, 100)} ({source})")
                shown += 1
            if len(findings_list) > 5:
                lines.append(f"    *...and {len(findings_list) - 5} more in this category*")
                shown += len(findings_list) - 5

    # ── Changed JS files ─────────────────────────────────────────────
    if changed_files:
        lines.extend(["", "📝 **Changed JS Files**"])
        for item in changed_files[:8]:
            status_icon = "🆕" if item.get('status') == 'new' else "🔄"
            lines.append(f"  {status_icon} {md_text(item.get('url', ''), 200)}")
        if len(changed_files) > 8:
            lines.append(f"  *...and {len(changed_files) - 8} more*")

    if result.get("skipped_deactivation"):
        lines.extend(
            [
                "",
                "⚠️ _Some pages/JS files failed to fetch — finding deactivation skipped._",
            ]
        )

    send_notify(cfg, "\n".join(lines).strip())


# -----------------------------
# Program scan
# -----------------------------

def program_workdir(base: Path, program_name: str) -> Path:
    return ensure_dir(base / safe_name(program_name))


def get_known_katana_urls(conn: sqlite3.Connection, program_id: int) -> set[str]:
    """Retrieve all previously stored Katana URLs for the given program."""
    cur = conn.cursor()
    known = set()
    for row in cur.execute("SELECT urls FROM katana_results WHERE program_id=?", (program_id,)):
        try:
            urls = json.loads(row["urls"])
            for u in urls:
                known.add(u)
        except Exception:
            pass
    return known


def _run_web_pipeline(
    cfg: Config,
    db_path: Path,
    program_id: int,
    program_name: str,
    roots: list[str],
    job_dir: Path,
    run_id: int,
) -> dict[str, Any]:
    """
    Web pipeline: subfinder → httpx → katana → 3-way parallel (nuclei, js_monitor).
    Runs in its own thread with its own DB connection so it never blocks the ASN pipeline.
    """
    conn = connect_db(db_path)
    cur = conn.cursor()
    result: dict[str, Any] = {
        "discovered": set(),
        "new_hosts": [],
        "seen_hosts": [],
        "httpx_results": [],
        "live_hosts": [],
        "katana_urls": [],
        "nuclei_findings": [],
        "js_monitor_result": {"status": "disabled"} if not cfg.js_monitor_enabled else None,
    }

    try:
        # ── Step 1: Subfinder ────────────────────────────────────────────
        discovered = run_subfinder(cfg, roots, job_dir)
        logging.info("[%s] Web Pipeline – subfinder completed", program_name)
        result["discovered"] = discovered

        new_hosts, seen_hosts = update_subdomains(conn, program_id, discovered)
        result["new_hosts"] = new_hosts
        result["seen_hosts"] = seen_hosts
        total_db_hosts = cur.execute(
            "SELECT COUNT(*) FROM subdomains WHERE program_id=?", (program_id,)
        ).fetchone()[0]

        if cfg.notify_step_by_step:
            if len(new_hosts) > 0:
                old_subdomains = total_db_hosts - len(new_hosts)
                msg = (
                    f"[{program_name}] **Subfinder finished**\n\n"
                    f"**old subdomains**\n- {old_subdomains}\n"
                    f"**new subdomains**\n- {len(new_hosts)}\n"
                    f"**total now**\n- {total_db_hosts}"
                )
            else:
                msg = (
                    f"[{program_name}] **Subfinder finished**\n\n"
                    f"**nothing new, total subdomains:**\n- {total_db_hosts}"
                )
            send_notify(cfg, msg)

        cur.execute(
            "UPDATE runs SET discovered=?, new_subdomains=? WHERE id=?",
            (len(discovered), len(new_hosts), run_id),
        )
        conn.commit()

        if new_hosts:
            (job_dir / "new_subdomains.txt").write_text(
                "\n".join(new_hosts) + "\n", encoding="utf-8"
            )

        # ── Step 2: HTTPX ────────────────────────────────────────────────
        httpx_results: list[dict[str, Any]] = []
        live_hosts: list[str] = []
        live_urls: list[str] = []
        if new_hosts:
            httpx_results, live_hosts = run_httpx(cfg, new_hosts, job_dir)
            logging.info("[%s] Web Pipeline – httpx completed", program_name)
            store_httpx(conn, program_id, httpx_results, job_dir)
            live_urls = sorted(
                set(r["url"] for r in httpx_results if r.get("alive") and r.get("url"))
            )
        else:
            logging.info(
                "[%s] Web Pipeline – no new subdomains for httpx; reusing known live URLs",
                program_name,
            )

        result["httpx_results"] = httpx_results
        result["live_hosts"] = live_hosts

        known_live_urls = get_known_live_urls(conn, program_id)
        crawl_seed_urls = filter_monitor_urls(
            sorted(set(known_live_urls + live_urls)),
            roots,
            cfg.js_monitor_allow_external,
            js_only=False,
        )
        (job_dir / "monitor_seed_urls.txt").write_text(
            "\n".join(crawl_seed_urls) + "\n", encoding="utf-8"
        )

        if cfg.notify_step_by_step and new_hosts:
            lines = [
                f"[{program_name}] **HTTPX finished**: "
                f"{len(live_hosts)} out of {len(new_hosts)} are live."
            ]
            if live_urls:
                lines.append("\n**Live urls**")
                for u in live_urls[:15]:
                    lines.append(f"- {u}")
                if len(live_urls) > 15:
                    lines.append(f"*...and {len(live_urls) - 15} more*")
            send_notify(cfg, "\n".join(lines).strip())

        if not crawl_seed_urls:
            logging.info("[%s] Web Pipeline – no URLs to crawl/scan, finishing", program_name)
            return result

        # ── Step 3: Parallel Katana and Naabu (Web Pipeline) ────────────
        known_katana_urls = get_known_katana_urls(conn, program_id)
        katana_urls = []
        web_port_results = []
        
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {}
            if live_hosts:
                futures[pool.submit(run_naabu, cfg, live_hosts, job_dir)] = "naabu"
            
            if cfg.katana_enabled:
                futures[pool.submit(run_katana, cfg, crawl_seed_urls, job_dir, roots)] = "katana"
            else:
                logging.info("[%s] Web Pipeline – katana disabled, re-using known URLs", program_name)
                katana_urls = list(known_katana_urls)

            for future in as_completed(futures):
                tool_name = futures[future]
                if tool_name == "naabu":
                    web_port_results = future.result()
                    logging.info("[%s] Web Pipeline – naabu completed: %d finding(s)", program_name, len(web_port_results))
                    store_ports(conn, program_id, web_port_results)
                    
                    if cfg.notify_step_by_step:
                        unique_ports = {}
                        for p in web_port_results:
                            host = p.get("host")
                            port = p.get("port")
                            if not host or not port:
                                continue
                            key = (host, port)
                            if key not in unique_ports:
                                unique_ports[key] = p
                            else:
                                if not unique_ports[key].get("version") and p.get("version"):
                                    unique_ports[key] = p
                        
                        host_port_map: dict[str, list[dict]] = {}
                        for p in unique_ports.values():
                            host_port_map.setdefault(p["host"], []).append(p)
                            
                        lines = [f"[{program_name}] **Web Naabu finished**: {len(unique_ports)} unique port findings\n"]
                        for host, ports in list(host_port_map.items())[:10]:
                            lines.append(f"**{host}**")
                            ports.sort(key=lambda x: int(x.get("port", 0)) if str(x.get("port", "0")).isdigit() else 0)
                            for p in ports:
                                port = p.get("port")
                                proto = p.get("protocol") or "tcp"
                                svc = p.get("service") or ""
                                prod = p.get("version") or ""
                                details = ": ".join(filter(None, [svc, prod]))
                                svc_str = f" ({details})" if details else ""
                                lines.append(f"- {port}/{proto}{svc_str}")
                            lines.append("")
                        
                        if len(host_port_map) > 10:
                            lines.append(f"*...and {len(host_port_map) - 10} more hosts*")
                            
                        if unique_ports:
                            send_notify(cfg, "\n".join(lines).strip())

                elif tool_name == "katana":
                    katana_urls = future.result()
                    logging.info("[%s] Web Pipeline – katana completed", program_name)
                    katana_parsed = parse_katana_results(job_dir, roots)
                    store_katana(conn, program_id, katana_parsed)
                    
                    if cfg.notify_step_by_step:
                        send_notify(
                            cfg,
                            f"[{program_name}] **Katana finished**: {len(katana_urls)} new URLs crawled.",
                        )

        result["katana_urls"] = katana_urls
        result["web_port_results"] = web_port_results

        # ── Split katana URLs into three categories ──────────────────────
        katana_js_urls: list[str] = []
        katana_param_urls: list[str] = []
        katana_normal_urls: list[str] = []

        for url in katana_urls:
            parsed = urllib.parse.urlparse(url)
            if is_probable_js_url(url):
                katana_js_urls.append(url)
            elif parsed.query:
                katana_param_urls.append(url)
            else:
                katana_normal_urls.append(url)

        katana_js_urls = dedupe_strings(katana_js_urls)
        katana_param_urls = dedupe_strings(katana_param_urls)
        katana_normal_urls = dedupe_strings(katana_normal_urls)

        (job_dir / "httpx_live_urls.txt").write_text(
            "\n".join(crawl_seed_urls) + "\n", encoding="utf-8"
        )
        (job_dir / "katana_js_urls.txt").write_text(
            "\n".join(katana_js_urls) + "\n", encoding="utf-8"
        )
        (job_dir / "katana_param_urls.txt").write_text(
            "\n".join(katana_param_urls) + "\n", encoding="utf-8"
        )
        (job_dir / "katana_normal_urls.txt").write_text(
            "\n".join(katana_normal_urls) + "\n", encoding="utf-8"
        )

        # Nuclei receives only NEW parameter-bearing URLs (not seen in previous runs)
        nuclei_scan_urls = dedupe_strings([u for u in katana_param_urls if u not in known_katana_urls])
        # JS monitor receives normal + param pages as HTML seeds, JS files as direct targets
        js_page_scan_urls = dedupe_strings(katana_normal_urls + katana_param_urls)
        js_direct_scan_urls = katana_js_urls

        # ── Step 4: 3-way parallel (nuclei + js_html + js_js) ───────────
        nuclei_findings: list[dict[str, Any]] = []
        js_monitor_result: Optional[dict[str, Any]] = (
            {"status": "disabled"} if not cfg.js_monitor_enabled else None
        )
        
        if not cfg.nuclei_enabled:
            logging.info("[%s] Web Pipeline – nuclei disabled", program_name)
            nuclei_scan_urls = []

        if not nuclei_scan_urls:
            logging.info("[%s] Web Pipeline – No new parameter URLs found, skipping Nuclei", program_name)

        if nuclei_scan_urls or cfg.js_monitor_enabled:
            logging.info(
                "[%s] Web Pipeline – post-katana parallel: nuclei=%d js_pages=%d js_direct=%d",
                program_name,
                len(nuclei_scan_urls),
                len(js_page_scan_urls),
                len(js_direct_scan_urls),
            )
            raw_js_monitor_result: Optional[dict[str, Any]] = None
            with ThreadPoolExecutor(max_workers=3) as pool:
                futures: dict[Any, str] = {}
                if nuclei_scan_urls:
                    futures[pool.submit(run_nuclei, cfg, nuclei_scan_urls, job_dir)] = "nuclei"
                if cfg.js_monitor_enabled:
                    futures[
                        pool.submit(
                            run_js_monitor_scan,
                            cfg,
                            js_page_scan_urls,
                            js_direct_scan_urls,
                            roots,
                            job_dir,
                        )
                    ] = "js_monitor"

                for future in as_completed(futures):
                    tool_name = futures[future]
                    try:
                        if tool_name == "nuclei":
                            nuclei_findings = future.result()
                            logging.info("[%s] Web Pipeline – nuclei completed", program_name)
                        elif tool_name == "js_monitor":
                            raw_js_monitor_result = future.result()
                            logging.info("[%s] Web Pipeline – JS monitor completed", program_name)
                    except Exception:
                        logging.exception("[%s] Web Pipeline – %s failed in post-katana stage", program_name, tool_name)

            if nuclei_findings:
                store_nuclei(conn, program_id, nuclei_findings)
            if cfg.notify_step_by_step and nuclei_scan_urls:
                send_notify(
                    cfg,
                    f"[{program_name}] **Nuclei finished**: {len(nuclei_findings)} vulnerabilities found.",
                )

            if raw_js_monitor_result is not None:
                js_monitor_result = store_js_monitor_results(
                    conn, program_id, run_id, raw_js_monitor_result, job_dir
                )
                logging.info(
                    "[%s] Web Pipeline – JS monitor saved: files=%d changed=%d new=%d removed=%d",
                    program_name,
                    len(js_monitor_result.get("discovered_js_urls", [])),
                    len(js_monitor_result.get("changed_files", [])),
                    len(js_monitor_result.get("new_findings", [])),
                    len(js_monitor_result.get("removed_findings", [])),
                )
                notify_js_monitor_findings(cfg, program_name, js_monitor_result)
        else:
            logging.info("[%s] Web Pipeline – no post-katana URLs for scanning", program_name)

        result["nuclei_findings"] = nuclei_findings
        result["js_monitor_result"] = js_monitor_result

    finally:
        conn.close()

    return result


def build_asn_pipeline_report(
    program_name: str,
    asn_ranges: list[dict[str, Any]],
    asn_ips: list[str],
    alive_ips: list[str],
    port_results: list[dict[str, Any]],
    httpx_results: list[dict[str, Any]],
) -> str:
    """Build a well-structured ASN pipeline summary notification."""
    # Collect unique ASNs
    unique_asns: set[str] = set()
    for r in asn_ranges:
        asn = r.get("asn", "").strip()
        if asn:
            unique_asns.add(asn)

    lines = [
        f"[{program_name}] **ASN Pipeline Summary**",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📡 **Ranges**: {len(asn_ranges)} CIDR range(s) from {len(unique_asns)} ASN(s)",
        f"🌐 **IPs**: {len(asn_ips)} expanded → {len(alive_ips)} alive",
    ]

    if not alive_ips:
        lines.append("\nNo alive IPs found.")
        return "\n".join(lines)

    # Build port map: ip -> list of port info
    port_map: dict[str, list[dict[str, Any]]] = {}
    for p in port_results:
        host = (p.get("host") or p.get("ip") or p.get("subdomain", "")).strip()
        if host:
            port_map.setdefault(host, []).append(p)

    # Build httpx map: (ip, port) -> httpx result
    httpx_map: dict[tuple[str, int], dict[str, Any]] = {}
    for h in httpx_results:
        ip = h.get("ip", "").strip()
        port = h.get("port")
        if ip and port:
            httpx_map[(ip, port)] = h

    lines.extend(["", "**Alive IPs & Open Ports**"])

    shown_hosts = 0
    for ip in alive_ips:
        if shown_hosts >= 15:
            remaining = len(alive_ips) - shown_hosts
            if remaining > 0:
                lines.append(f"\n*...and {remaining} more host(s)*")
            break

        ip_ports = port_map.get(ip, [])
        # Sort ports numerically
        ip_ports.sort(
            key=lambda x: int(x.get("port", 0))
            if str(x.get("port", "0")).isdigit()
            else 0
        )

        lines.append(f"\n🔹 **{ip}**")
        if not ip_ports:
            lines.append("  • No open ports detected")
        else:
            for p in ip_ports:
                port_num = p.get("port")
                proto = p.get("protocol") or "tcp"
                svc = p.get("service") or ""
                ver = p.get("version") or ""

                # Check httpx result for this IP:port
                hx = httpx_map.get((ip, port_num), {})
                status = hx.get("status_code")
                title = hx.get("title", "")

                port_str = f"{port_num}/{proto}"
                svc_detail = ": ".join(filter(None, [svc, ver]))
                if svc_detail:
                    port_str += f" ({svc_detail})"

                if status or title:
                    http_info = " → "
                    parts = []
                    if status:
                        parts.append(str(status))
                    if title:
                        parts.append(md_text(title, 80))
                    http_info += " | ".join(parts)
                    port_str += http_info

                lines.append(f"  • {port_str}")

        shown_hosts += 1

    return "\n".join(lines)


def _run_asn_pipeline(
    cfg: Config,
    db_path: Path,
    program_id: int,
    program_name: str,
    roots: list[str],
    job_dir: Path,
) -> dict[str, Any]:
    """
    ASN pipeline: asnmap → mapcidr → naabu (alive IPs + open ports) → httpx (status + title).
    Runs in its own thread with its own DB connection so it never blocks the web pipeline.
    Sends a single consolidated notification at the end.
    """
    conn = connect_db(db_path)
    result: dict[str, Any] = {
        "asn_ranges": [],
        "asn_ips": [],
        "asn_alive_ips": [],
        "port_results": [],
        "asn_httpx_results": [],
    }

    try:
        if not cfg.asn_enabled:
            logging.info("[%s] ASN Pipeline – disabled via ASN_ENABLED=false", program_name)
            return result

        # ── Step 1: ASN recon (asnmap → mapcidr → naabu) ─────────────────
        asn_ranges, asn_ips, asn_alive_ips, port_results = run_asn_recon(cfg, roots, job_dir)
        result["asn_ranges"] = asn_ranges
        result["asn_ips"] = asn_ips
        result["asn_alive_ips"] = asn_alive_ips
        result["port_results"] = port_results

        store_asn_ranges(conn, program_id, asn_ranges)
        store_asn_ips(conn, program_id, asn_ips)
        mark_asn_ips_alive(conn, program_id, asn_alive_ips)
        store_ports(conn, program_id, port_results)
        logging.info(
            "[%s] ASN Pipeline – recon completed: %d range(s), %d IP(s) expanded, %d alive, %d port(s)",
            program_name,
            len(asn_ranges),
            len(asn_ips),
            len(asn_alive_ips),
            len(port_results),
        )

        # ── Step 2: httpx on alive IPs with open ports ───────────────────
        asn_httpx = []
        if port_results:
            asn_httpx = run_asn_httpx(cfg, port_results, job_dir, log_prefix="[ASN Pipeline]")
            result["asn_httpx_results"] = asn_httpx
            store_asn_httpx(conn, program_id, asn_httpx)
            logging.info(
                "[%s] ASN Pipeline – httpx completed: %d result(s)",
                program_name,
                len(asn_httpx),
            )
        else:
            logging.info("[%s] ASN Pipeline – no port results, skipping httpx", program_name)

        # ── Single consolidated notification ─────────────────────────────
        if cfg.notify_bin and asn_ranges:
            report = build_asn_pipeline_report(
                program_name,
                asn_ranges,
                asn_ips,
                asn_alive_ips,
                port_results,
                asn_httpx,
            )
            try:
                send_notify(cfg, report)
            except Exception as exc:
                logging.error("ASN pipeline notify failed for %s: %s", program_name, exc)

    finally:
        conn.close()

    return result


def run_program_cycle(cfg: Config, conn: sqlite3.Connection, program: sqlite3.Row) -> None:
    """
    Orchestrator: launches the web pipeline and ASN pipeline as two fully independent
    threads, waits for both, then merges results for the final summary and DB update.
    """
    cur = conn.cursor()
    program_id = int(program["id"])
    program_name = str(program["name"])
    job_dir = ensure_dir(
        program_workdir(cfg.workdir, program_name)
        / dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    )

    roots = scope_roots_for_program(conn, program_id)
    if not roots:
        logging.info("[%s] no scope roots found, skipping", program_name)
        return

    cur.execute(
        "INSERT INTO runs (program_id, started_at) VALUES (?, ?)",
        (program_id, utc_now()),
    )
    run_id = cur.lastrowid
    conn.commit()

    try:
        web_result: dict[str, Any] = {}
        asn_result: dict[str, Any] = {}

        # Launch both pipelines in fully independent threads
        with ThreadPoolExecutor(max_workers=2) as pool:
            web_future = pool.submit(
                _run_web_pipeline,
                cfg, cfg.db_path, program_id, program_name, roots, job_dir, run_id,
            )
            asn_future = pool.submit(
                _run_asn_pipeline,
                cfg, cfg.db_path, program_id, program_name, roots, job_dir,
            )

            for future in as_completed({web_future: "web", asn_future: "asn"}):
                label = {web_future: "web", asn_future: "asn"}[future]
                try:
                    if label == "web":
                        web_result = future.result()
                        logging.info("[%s] [DONE] Web pipeline finished", program_name)
                    else:
                        asn_result = future.result()
                        logging.info("[%s] [DONE] ASN pipeline finished", program_name)
                except Exception:
                    logging.exception("[%s] %s pipeline failed", program_name, label)

        # ── Merge results and update the runs table ──────────────────────
        discovered = web_result.get("discovered", set())
        new_hosts = web_result.get("new_hosts", [])
        seen_hosts = web_result.get("seen_hosts", [])
        httpx_results = web_result.get("httpx_results", [])
        live_hosts = web_result.get("live_hosts", [])
        katana_urls = web_result.get("katana_urls", [])
        nuclei_findings = web_result.get("nuclei_findings", [])
        js_monitor_result = web_result.get("js_monitor_result")
        
        web_port_results = web_result.get("web_port_results", [])
        asn_port_results = asn_result.get("port_results", [])
        port_results = web_port_results + asn_port_results

        cur.execute(
            """
            UPDATE runs
            SET finished_at=?, status='ok', live_subdomains=?, nuclei_findings=?, katana_urls=?
            WHERE id=?
            """,
            (utc_now(), len(live_hosts), len(nuclei_findings), len(katana_urls), run_id),
        )
        cur.execute(
            "UPDATE programs SET last_scanned_at=?, updated_at=? WHERE id=?",
            (utc_now(), utc_now(), program_id),
        )
        conn.commit()

        notify_program_summary(
            cfg,
            program_name,
            roots,
            job_dir,
            len(discovered),
            new_hosts,
            seen_hosts,
            httpx_results,
            live_hosts,
            port_results,
            nuclei_findings,
            len(katana_urls),
            js_monitor_result,
        )

    except Exception:
        cur.execute(
            "UPDATE runs SET finished_at=?, status='error' WHERE id=?",
            (utc_now(), run_id),
        )
        conn.commit()
        raise


# -----------------------------
# .env file loader
# -----------------------------

def read_env_file(path: Path) -> dict[str, str]:
    """Read KEY=VALUE entries from a .env file without modifying os.environ."""
    if not path.exists():
        return {}

    env_vars: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="ignore").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            logging.warning(".env:%d: malformed line (no '=' found): %s", line_number, raw_line.strip())
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        env_vars[key] = value

    return env_vars


# All required .env keys and their descriptions
REQUIRED_ENV_KEYS = {
    # Paths & storage
    "ROOT_DIR":          "Base directory for all script data (logs, targets, work, db)",
    # Notifications
    "NOTIFY_BIN":        "Path to notify binary (projectdiscovery)",
    "NOTIFY_ID":         "Optional provider ID for notify (leave blank for default)",
    "NOTIFY_STEP_BY_STEP": "Send alerts after each step (true/false)",
    # Tool binaries
    "SUBFINDER_BIN":     "Path to subfinder binary",
    "HTTPX_BIN":         "Path to httpx binary",
    "NAABU_BIN":         "Path to naabu binary",
    "NUCLEI_BIN":        "Path to nuclei binary",
    "KATANA_BIN":        "Path to katana binary",
    # Scan options
    "NUCLEI_ENABLED":    "Enable nuclei scanning (true/false, default: true)",
    "NUCLEI_SEVERITIES": "Nuclei severity filter (e.g. medium,high,critical)",
    "KATANA_ENABLED":    "Enable katana crawling (true/false, default: true)",
    "KATANA_DEPTH":      "Katana crawl depth (default: 3)",
    "KATANA_HEADLESS":   "Enable katana headless browser mode (true/false)",
    "KATANA_FIELD_SCOPE":"Field scope for katana (-fs) (default: rdn)",
    "KATANA_CUSTOM_SCOPE":"Custom regex scope for katana (-cs) (default: empty)",
    "SUBFINDER_ARGS":    "Extra subfinder args (e.g. '-all -active')",
    "HTTPX_TIMEOUT":     "HTTPX timeout in seconds",
    "NAABU_TIMEOUT":     "Naabu timeout in seconds",
    "NAABU_NMAP_CLI":    "Enable Nmap service detection in Naabu (true/false)",
    "NUCLEI_TIMEOUT":    "Nuclei timeout in seconds",
    "KATANA_TIMEOUT":    "Katana crawling timeout in seconds",
    # Maintenance
    "MAX_JOB_RETENTION_DAYS": "Auto-delete scan output older than N days (0=disable)",
    # Debug
    "DRY_RUN":           "Skip running external tools (true/false)",
}


# Keys that must contain valid positive integers
TIMEOUT_KEYS = {
    "SUBFINDER_TIMEOUT", "HTTPX_TIMEOUT", "NAABU_TIMEOUT",
    "NUCLEI_TIMEOUT", "KATANA_TIMEOUT", "KATANA_DEPTH",
    "MAX_JOB_RETENTION_DAYS", "JS_MONITOR_THREADS", "JS_MONITOR_TIMEOUT",
    "JS_MONITOR_TOOL_TIMEOUT", "JS_MONITOR_RECURSION_DEPTH",
}

# Keys that are allowed to be empty or missing
ALLOW_EMPTY_KEYS = {
    "NOTIFY_ID",
    "KATANA_CUSTOM_SCOPE",
    "SUBFINDER_ARGS",
    "HTTPX_ARGS",
    "NAABU_ARGS",
    "NUCLEI_ARGS",
    "KATANA_ARGS",
    "NOTIFY_ARGS",
}


def validate_env(env: dict[str, str], env_file: Path) -> None:
    """Check that every required key is present, non-empty, and valid. Exit with clear error if not."""
    missing: list[str] = []
    empty: list[str] = []
    invalid: list[str] = []

    for key, description in REQUIRED_ENV_KEYS.items():
        if key not in env:
            if key not in ALLOW_EMPTY_KEYS:
                missing.append(f"  {key:25s} - {description}")
        elif not env[key].strip() or env[key].strip().startswith("your_"):
            if key not in ALLOW_EMPTY_KEYS:
                empty.append(f"  {key:25s} - {description} (current: '{env[key]}')")
        elif key in TIMEOUT_KEYS:
            try:
                val = int(env[key])
                if val < 0:
                    raise ValueError("negative")
            except ValueError:
                invalid.append(f"  {key:25s} - must be a non-negative integer (current: '{env[key]}')")

    for key in sorted(TIMEOUT_KEYS - set(REQUIRED_ENV_KEYS)):
        if key not in env or not env[key].strip():
            continue
        try:
            val = int(env[key])
            if val < 0:
                raise ValueError("negative")
        except ValueError:
            invalid.append(f"  {key:25s} - must be a non-negative integer (current: '{env[key]}')")

    if missing or empty or invalid:
        logging.error("=" * 65)
        logging.error(".env CONFIGURATION ERROR")
        logging.error("=" * 65)
        if missing:
            logging.error("Missing keys (%d):", len(missing))
            for line in missing:
                logging.error(line)
        if empty:
            logging.error("Keys with placeholder/empty values (%d):", len(empty))
            for line in empty:
                logging.error(line)
        if invalid:
            logging.error("Keys with invalid values (%d):", len(invalid))
            for line in invalid:
                logging.error(line)
        logging.error("File: %s", env_file)
        logging.error("Fix the .env file and restart the service.")
        logging.error("=" * 65)
        sys.exit(1)


def load_config() -> Config:
    """Load and validate all configuration from .env file beside the script."""
    script_dir = Path(__file__).resolve().parent
    env_file = script_dir / ".env"

    if not env_file.exists():
        logging.error("=" * 65)
        logging.error("FATAL: .env file not found!")
        logging.error("Expected: %s", env_file)
        logging.error("Copy .env.example to .env and configure all values.")
        logging.error("=" * 65)
        sys.exit(1)

    env = read_env_file(env_file)
    validate_env(env, env_file)
    js_patterns_file = env.get("JS_MONITOR_PATTERNS_FILE", "").strip()
    if js_patterns_file:
        js_patterns_path = Path(js_patterns_file).expanduser()
        if not js_patterns_path.is_absolute():
            js_patterns_path = script_dir / js_patterns_path
        js_patterns_file = str(js_patterns_path)

    return Config(
        root_dir=Path(env["ROOT_DIR"]).expanduser(),
        notify_bin=env["NOTIFY_BIN"],
        notify_id=env["NOTIFY_ID"].strip(),
        notify_step_by_step=env["NOTIFY_STEP_BY_STEP"].strip().lower() in ("true", "1", "yes"),
        subfinder_bin=env["SUBFINDER_BIN"],
        httpx_bin=env["HTTPX_BIN"],
        naabu_bin=env["NAABU_BIN"],
        nuclei_bin=env["NUCLEI_BIN"],
        katana_bin=env["KATANA_BIN"],
        nuclei_enabled=env.get("NUCLEI_ENABLED", "true").strip().lower() in ("true", "1", "yes"),
        nuclei_severities=env["NUCLEI_SEVERITIES"],
        subfinder_timeout=int(env["SUBFINDER_TIMEOUT"]),
        httpx_timeout=int(env["HTTPX_TIMEOUT"]),
        naabu_timeout=int(env["NAABU_TIMEOUT"]),
        naabu_nmap_cli=env.get("NAABU_NMAP_CLI", "false").strip().lower() in ("true", "1", "yes"),
        nuclei_timeout=int(env["NUCLEI_TIMEOUT"]),
        katana_enabled=env.get("KATANA_ENABLED", "true").strip().lower() in ("true", "1", "yes"),
        katana_timeout=int(env["KATANA_TIMEOUT"]),
        katana_depth=int(env["KATANA_DEPTH"]),
        katana_headless=env["KATANA_HEADLESS"].strip().lower() in ("true", "1", "yes"),
        katana_crawl_js=env.get("KATANA_CRAWL_JS", "true").strip().lower() in ("true", "1", "yes"),
        katana_jsluice=env.get("KATANA_JSLUICE", "false").strip().lower() in ("true", "1", "yes"),
        katana_field_scope=env.get("KATANA_FIELD_SCOPE", "rdn"),
        katana_custom_scope=env.get("KATANA_CUSTOM_SCOPE", ""),
        asnmap_bin=env.get("ASNMAP_BIN", "asnmap"),
        mapcidr_bin=env.get("MAPCIDR_BIN", "mapcidr"),
        asn_enabled=env.get("ASN_ENABLED", "true").strip().lower() in ("true", "1", "yes"),
        asn_timeout=int(env.get("ASN_TIMEOUT", "900")),
        mapcidr_timeout=int(env.get("MAPCIDR_TIMEOUT", "300")),
        asn_alive_timeout=int(env.get("ASN_ALIVE_TIMEOUT", "1800")),
        asn_max_ips=int(env.get("ASN_MAX_IPS", "65536")),
        asn_exclude_cdn=env.get("ASN_EXCLUDE_CDN", "true").strip().lower() in ("true", "1", "yes"),
        subfinder_provider_config=env.get("SUBFINDER_PROVIDER_CONFIG", ""),
        subfinder_args=env.get("SUBFINDER_ARGS", ""),
        httpx_args=env.get("HTTPX_ARGS", ""),
        naabu_args=env.get("NAABU_ARGS", ""),
        nuclei_args=env.get("NUCLEI_ARGS", ""),
        katana_args=env.get("KATANA_ARGS", ""),
        asnmap_args=env.get("ASNMAP_ARGS", ""),
        notify_args=env.get("NOTIFY_ARGS", ""),
        js_monitor_enabled=env.get("JS_MONITOR_ENABLED", "true").strip().lower() in ("true", "1", "yes"),
        js_monitor_threads=int(env.get("JS_MONITOR_THREADS", "15")),
        js_monitor_timeout=int(env.get("JS_MONITOR_TIMEOUT", "30")),
        js_monitor_tool_timeout=int(env.get("JS_MONITOR_TOOL_TIMEOUT", "900")),
        js_monitor_recursion_depth=int(env.get("JS_MONITOR_RECURSION_DEPTH", "3")),
        js_monitor_deep=env.get("JS_MONITOR_DEEP", "false").strip().lower() in ("true", "1", "yes"),
        js_monitor_patterns_file=js_patterns_file,
        js_monitor_allow_external=env.get("JS_MONITOR_ALLOW_EXTERNAL", "false").strip().lower() in ("true", "1", "yes"),
        max_job_retention_days=int(env["MAX_JOB_RETENTION_DAYS"]),
        dry_run=env["DRY_RUN"].strip().lower() in ("true", "1", "yes"),
    )



# File locking (service safety)
# -----------------------------

def acquire_lock(workdir: Path) -> Optional[Any]:
    """Acquire exclusive file lock to prevent concurrent scan instances."""
    lock_path = workdir / ".recon.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = open(lock_path, "w")
    try:
        import fcntl
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except ImportError:
        pass  # Non-POSIX system (Windows), skip locking
    except BlockingIOError:
        logging.error("Another scan instance is already running. Exiting.")
        lock_file.close()
        sys.exit(0)
    return lock_file


# -----------------------------
# Artifact cleanup
# -----------------------------

def cleanup_old_jobs(workdir: Path, max_days: int) -> None:
    """Remove job directories older than max_days to free disk space."""
    if max_days <= 0:
        return
    cutoff = dt.datetime.now() - dt.timedelta(days=max_days)
    removed = 0
    for program_dir in workdir.iterdir():
        if not program_dir.is_dir() or program_dir.name.startswith("."):
            continue
        for job_dir in program_dir.iterdir():
            if not job_dir.is_dir():
                continue
            try:
                mtime = dt.datetime.fromtimestamp(job_dir.stat().st_mtime)
                if mtime < cutoff:
                    shutil.rmtree(job_dir)
                    removed += 1
            except Exception as exc:
                logging.warning("Failed to clean up %s: %s", job_dir, exc)
    if removed:
        logging.info("Cleaned up %d old job dir(s) older than %d days", removed, max_days)


# -----------------------------
# Main execution
# -----------------------------

def run_cycle(cfg: Config) -> None:
    cfg.targets_dir.mkdir(parents=True, exist_ok=True)
    conn = connect_db(cfg.db_path)

    try:
        programs = sync_targets_dir(conn, cfg.targets_dir)
        logging.info("Loaded %d enabled program(s)", len(programs))

        for program in programs:
            run_program_cycle(cfg, conn, program)

    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Bug Bounty Auto Recon")
    parser.add_argument("-d", "--domain", help="Domain to add and initialize (e.g. example.com)")
    parser.add_argument("--setup", action="store_true", help="Initialize the directory structure and database")
    args = parser.parse_args()

    cfg = load_config()

    if args.setup:
        try:
            cfg.root_dir.mkdir(parents=True, exist_ok=True)
            cfg.targets_dir.mkdir(parents=True, exist_ok=True)
            cfg.workdir.mkdir(parents=True, exist_ok=True)
            cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
            connect_db(cfg.db_path).close()
            
            setup_logging(cfg.log_file)
            logging.info("Setup complete. Initialized structure in %s", cfg.root_dir)
            return 0
        except PermissionError as e:
            print(f"FATAL: Permission denied while trying to create directories in '{cfg.root_dir}'.")
            print("Please ensure you have write permissions or run the setup command with elevated privileges (e.g., sudo).")
            return 1
        except Exception as e:
            print(f"FATAL: An error occurred during setup: {e}")
            return 1

    # Ensure root_dir exists before proceeding to normal execution
    if not cfg.root_dir.exists() or not cfg.targets_dir.exists() or not cfg.workdir.exists() or not cfg.db_path.exists() or not cfg.log_file.parent.exists():
        print(f"Error: Essential directories or database not found in {cfg.root_dir}. Run with --setup first.")
        return 1

    setup_logging(cfg.log_file)

    # Bootstrap logic via CLI
    if args.domain:
        domain = args.domain.strip().lower()
        if " " in domain or "." not in domain:
            logging.error("Invalid domain format. Example: example.com")
            return 1
            
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        domain = domain.rstrip("/").rstrip(".")
        
        program_name = domain.replace(".", "_")
        
        target_file = cfg.targets_dir / f"{program_name}.txt"
        target_file.write_text(domain + "\n", encoding="utf-8")
        
        logging.info("Created target: %s", target_file)
        logging.info("Scope domain: %s", domain)
        logging.info("Program name: %s", program_name)

    # Check if we have targets to run
    target_files = [p for p in cfg.targets_dir.iterdir() if p.is_file() and not p.name.startswith(".")]
    if not target_files:
        logging.error("No target files found in '%s'. Add a target via -d <domain>.", cfg.targets_dir)
        return 1

    # Acquire file lock to prevent concurrent instances (service safety)
    lock_file = acquire_lock(cfg.workdir)

    logging.info("Config loaded from .env")
    logging.info("Root dir: %s", cfg.root_dir)
    logging.info("Targets dir: %s", cfg.targets_dir)
    logging.info("Database: %s", cfg.db_path)
    logging.info("Workdir: %s", cfg.workdir)
    logging.info("Log file: %s", cfg.log_file)
    if cfg.dry_run:
        logging.info("DRY_RUN mode enabled — external tools will not be executed")

    try:
        # Clean up old scan output before starting
        cleanup_old_jobs(cfg.workdir, cfg.max_job_retention_days)
        run_cycle(cfg)
    except KeyboardInterrupt:
        print("\nScan interrupted by user (Ctrl+C). Exiting gracefully...")
        logging.info("Scan interrupted by user (KeyboardInterrupt).")
        if 'lock_file' in locals() and lock_file:
            lock_file.close()
        import os
        os._exit(1)
    except subprocess.TimeoutExpired as exc:
        logging.exception("Timeout: %s", exc)
        return 1
    except Exception as exc:
        logging.exception("Scan failed: %s", exc)
        return 1
    finally:
        if lock_file:
            lock_file.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
