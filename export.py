#!/usr/bin/env python3
"""
export.py

Export tool for recon.py database.
Generates interactive HTML reports and JSON exports with advanced filtering.

Usage:
    python export.py --db /path/to/recon.db --program "company_1"
    python export.py --db /path/to/recon.db --all-programs --output ./reports
    python export.py --db /path/to/recon.db --list-programs
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from html import escape


# =============================================================================
# Data Models (unchanged)
# =============================================================================

@dataclass
class Program:
    id: int
    name: str
    scope_file: str
    enabled: bool
    created_at: str
    updated_at: str
    last_scanned_at: Optional[str]
    scope_domains: list[str] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)


@dataclass
class Subdomain:
    id: int
    host: str
    first_seen: str
    last_seen: str
    alive: bool
    http_url: Optional[str]
    http_status: Optional[int]
    http_title: Optional[str]
    http_tech: Optional[str]
    screenshot_path: Optional[str]
    last_httpx_at: Optional[str]
    last_naabu_at: Optional[str]
    last_nuclei_at: Optional[str]
    ports: list[str] = field(default_factory=list)
    nuclei_count: int = 0


@dataclass
class HttpxResult:
    id: int
    subdomain: str
    scanned_at: str
    url: Optional[str]
    status_code: Optional[int]
    title: Optional[str]
    tech: Optional[str]
    webserver: Optional[str]
    host_ip: Optional[str]
    cname: Optional[str]
    port: Optional[int]
    scheme: Optional[str]
    content_type: Optional[str]
    method: Optional[str]
    path: Optional[str]
    cdn_name: Optional[str]
    cdn_type: Optional[str]


@dataclass
class PortResult:
    id: int
    subdomain: str
    scanned_at: str
    host: Optional[str]
    ip: Optional[str]
    open_ports: str


@dataclass
class NucleiFinding:
    id: int
    subdomain: str
    url: Optional[str]
    scanned_at: str
    severity: Optional[str]
    template_id: Optional[str]
    name: Optional[str]
    matched_at: Optional[str]


@dataclass
class KatanaUrl:
    id: int
    subdomain: str
    scanned_at: str
    url: str
    source_type: str = "katana"


@dataclass
class JsFile:
    id: int
    url: str
    source_url: Optional[str]
    current_hash: Optional[str]
    content_length: Optional[int]
    first_seen_at: str
    last_seen_at: str
    last_changed_at: Optional[str]
    is_active: bool


@dataclass
class JsFinding:
    id: int
    source_url: Optional[str]
    source_type: str
    category: str
    value: str
    context: Optional[str]
    first_seen_at: str
    last_seen_at: str
    is_active: bool


@dataclass
class AsnRange:
    id: int
    asn: str
    org: Optional[str]
    cidr: str
    discovered_at: str
    ip_count: int = 0


@dataclass
class AsnIp:
    id: int
    ip: str
    cidr: Optional[str]
    asn: Optional[str]
    alive: bool
    first_seen: str
    last_seen: str


@dataclass
class RunHistory:
    id: int
    started_at: str
    finished_at: Optional[str]
    discovered: int
    new_subdomains: int
    live_subdomains: int
    nuclei_findings: int
    katana_urls: int
    js_files_found: int
    js_files_changed: int
    js_findings_total: int
    js_findings_new: int
    js_findings_critical: int
    status: str


@dataclass
class ExportData:
    program: Program
    subdomains: list[Subdomain] = field(default_factory=list)
    httpx_results: list[HttpxResult] = field(default_factory=list)
    port_results: list[PortResult] = field(default_factory=list)
    nuclei_findings: list[NucleiFinding] = field(default_factory=list)
    katana_urls: list[KatanaUrl] = field(default_factory=list)
    js_files: list[JsFile] = field(default_factory=list)
    js_findings: list[JsFinding] = field(default_factory=list)
    asn_ranges: list[AsnRange] = field(default_factory=list)
    asn_ips: list[AsnIp] = field(default_factory=list)
    run_history: list[RunHistory] = field(default_factory=list)
    exported_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "exported_at": self.exported_at,
            "program": asdict(self.program),
            "summary": self.get_summary(),
            "subdomains": [asdict(s) for s in self.subdomains],
            "httpx_results": [asdict(h) for h in self.httpx_results],
            "port_results": [asdict(p) for p in self.port_results],
            "nuclei_findings": [asdict(n) for n in self.nuclei_findings],
            "katana_urls": [asdict(k) for k in self.katana_urls],
            "js_files": [asdict(j) for j in self.js_files],
            "js_findings": [asdict(j) for j in self.js_findings],
            "asn_ranges": [asdict(a) for a in self.asn_ranges],
            "asn_ips": [asdict(a) for a in self.asn_ips],
            "run_history": [asdict(r) for r in self.run_history],
        }

    def get_summary(self) -> dict[str, Any]:
        all_ports = set()
        for pr in self.port_results:
            for p in pr.open_ports.split(","):
                p = p.strip()
                if p:
                    all_ports.add(p)
        return {
            "total_subdomains": len(self.subdomains),
            "alive_subdomains": sum(1 for s in self.subdomains if s.alive),
            "dead_subdomains": sum(1 for s in self.subdomains if not s.alive),
            "unique_urls": len(set(h.url for h in self.httpx_results if h.url)),
            "total_ports": len(self.port_results),
            "unique_open_ports": len(all_ports),
            "nuclei_findings": len(self.nuclei_findings),
            "nuclei_by_severity": self._count_by_severity(),
            "katana_urls": len(self.katana_urls),
            "unique_katana_urls": len(set(k.url for k in self.katana_urls)),
            "js_files": len(self.js_files),
            "active_js_files": sum(1 for j in self.js_files if j.is_active),
            "inactive_js_files": sum(1 for j in self.js_files if not j.is_active),
            "js_findings": len(self.js_findings),
            "js_findings_by_category": self._count_js_categories(),
            "critical_js_findings": self._count_critical_js(),
            "asn_ranges": len(self.asn_ranges),
            "asn_ips": len(self.asn_ips),
            "alive_asn_ips": sum(1 for a in self.asn_ips if a.alive),
            "total_runs": len(self.run_history),
            "last_run": self.run_history[0].started_at if self.run_history else None,
            "status_codes": self._count_status_codes(),
        }

    def _count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        for f in self.nuclei_findings:
            sev = (f.severity or "unknown").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_js_categories(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.js_findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))

    def _count_critical_js(self) -> int:
        critical_categories = {"api_key", "aws_key", "aws_secret", "google_api_key", "credential", "jwt"}
        return sum(1 for f in self.js_findings if f.category in critical_categories and f.is_active)

    def _count_status_codes(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for h in self.httpx_results:
            code = str(h.status_code or "unknown")
            # Group by hundred
            if code.isdigit():
                group = code[0] + "xx"
            else:
                group = "other"
            counts[group] = counts.get(group, 0) + 1
        return dict(sorted(counts.items()))


# =============================================================================
# Database Extraction
# =============================================================================

class DatabaseExtractor:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {self.db_path}")
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None

    def list_programs(self) -> list[dict[str, Any]]:
        if not self.conn:
            self.connect()
        rows = self.conn.execute(
            "SELECT id, name, enabled, last_scanned_at, created_at FROM programs ORDER BY name"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_program_id(self, program_name: str) -> Optional[int]:
        if not self.conn:
            self.connect()
        row = self.conn.execute(
            "SELECT id FROM programs WHERE name = ?", (program_name,)
        ).fetchone()
        return row["id"] if row else None

    def extract_program(self, program_id: int, severity_filter: Optional[list[str]] = None) -> ExportData:
        if not self.conn:
            self.connect()

        prog_row = self.conn.execute(
            "SELECT * FROM programs WHERE id = ?", (program_id,)
        ).fetchone()
        if not prog_row:
            raise ValueError(f"Program ID {program_id} not found")

        scope_rows = self.conn.execute(
            "SELECT root_domain FROM scope_domains WHERE program_id = ? ORDER BY root_domain",
            (program_id,)
        ).fetchall()
        scope_domains = [r["root_domain"] for r in scope_rows]

        stats = self._get_program_stats(program_id)

        program = Program(
            id=prog_row["id"],
            name=prog_row["name"],
            scope_file=prog_row["scope_file"],
            enabled=bool(prog_row["enabled"]),
            created_at=prog_row["created_at"],
            updated_at=prog_row["updated_at"],
            last_scanned_at=prog_row["last_scanned_at"],
            scope_domains=scope_domains,
            stats=stats,
        )

        data = ExportData(
            program=program,
            exported_at=datetime.utcnow().isoformat(timespec="seconds") + "Z",
        )

        data.subdomains = self._extract_subdomains(program_id)
        data.httpx_results = self._extract_httpx_results(program_id)
        data.port_results = self._extract_port_results(program_id)
        data.nuclei_findings = self._extract_nuclei_findings(program_id, severity_filter)
        data.katana_urls = self._extract_katana_urls(program_id)
        data.js_files = self._extract_js_files(program_id)
        data.js_findings = self._extract_js_findings(program_id)
        data.asn_ranges = self._extract_asn_ranges(program_id)
        data.asn_ips = self._extract_asn_ips(program_id)
        data.run_history = self._extract_run_history(program_id)

        return data

    def _get_program_stats(self, program_id: int) -> dict[str, int]:
        stats = {}
        for table, col in [
            ("subdomains", "host"),
            ("httpx_results", "id"),
            ("ports", "id"),
            ("nuclei_findings", "id"),
            ("katana_results", "id"),
            ("js_files", "id"),
            ("js_findings", "id"),
            ("asn_ranges", "id"),
            ("asn_ips", "ip"),
            ("runs", "id"),
        ]:
            row = self.conn.execute(
                f"SELECT COUNT({col}) as cnt FROM {table} WHERE program_id = ?",
                (program_id,)
            ).fetchone()
            stats[table] = row["cnt"]
        return stats

    def _extract_subdomains(self, program_id: int) -> list[Subdomain]:
        rows = self.conn.execute(
            """
            SELECT s.*,
                   COALESCE(pr.ports, '') as port_list,
                   COALESCE(nf.cnt, 0) as nuclei_count
            FROM subdomains s
            LEFT JOIN (
                SELECT subdomain, GROUP_CONCAT(open_ports, ',') as ports
                FROM ports WHERE program_id = ?
                GROUP BY subdomain
            ) pr ON s.host = pr.subdomain
            LEFT JOIN (
                SELECT subdomain, COUNT(*) as cnt
                FROM nuclei_findings WHERE program_id = ?
                GROUP BY subdomain
            ) nf ON s.host = nf.subdomain
            WHERE s.program_id = ?
            ORDER BY s.alive DESC, s.host
            """,
            (program_id, program_id, program_id),
        ).fetchall()
        return [
            Subdomain(
                id=r["id"],
                host=r["host"],
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
                alive=bool(r["alive"]),
                http_url=r["http_url"],
                http_status=r["http_status"],
                http_title=r["http_title"],
                http_tech=r["http_tech"],
                screenshot_path=r["screenshot_path"],
                last_httpx_at=r["last_httpx_at"],
                last_naabu_at=r["last_naabu_at"],
                last_nuclei_at=r["last_nuclei_at"],
                ports=r["port_list"].split(",") if r["port_list"] else [],
                nuclei_count=r["nuclei_count"],
            )
            for r in rows
        ]

    def _extract_httpx_results(self, program_id: int) -> list[HttpxResult]:
        rows = self.conn.execute(
            "SELECT * FROM httpx_results WHERE program_id = ? ORDER BY scanned_at DESC",
            (program_id,),
        ).fetchall()
        return [
            HttpxResult(
                id=r["id"],
                subdomain=r["subdomain"],
                scanned_at=r["scanned_at"],
                url=r["url"],
                status_code=r["status_code"],
                title=r["title"],
                tech=r["tech"],
                webserver=r["webserver"],
                host_ip=r["host_ip"],
                cname=r["cname"],
                port=r["port"],
                scheme=r["scheme"],
                content_type=r["content_type"],
                method=r["method"],
                path=r["path"],
                cdn_name=r["cdn_name"],
                cdn_type=r["cdn_type"],
            )
            for r in rows
        ]

    def _extract_port_results(self, program_id: int) -> list[PortResult]:
        rows = self.conn.execute(
            "SELECT * FROM ports WHERE program_id = ? ORDER BY scanned_at DESC",
            (program_id,),
        ).fetchall()
        return [
            PortResult(
                id=r["id"],
                subdomain=r["subdomain"],
                scanned_at=r["scanned_at"],
                host=r["host"],
                ip=r["ip"],
                open_ports=r["open_ports"],
            )
            for r in rows
        ]

    def _extract_nuclei_findings(
        self, program_id: int, severity_filter: Optional[list[str]] = None
    ) -> list[NucleiFinding]:
        query = "SELECT * FROM nuclei_findings WHERE program_id = ?"
        params: list[Any] = [program_id]

        if severity_filter:
            placeholders = ",".join("?" * len(severity_filter))
            query += f" AND LOWER(severity) IN ({placeholders})"
            params.extend([s.lower() for s in severity_filter])

        query += " ORDER BY CASE LOWER(severity) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, scanned_at DESC"

        rows = self.conn.execute(query, params).fetchall()
        return [
            NucleiFinding(
                id=r["id"],
                subdomain=r["subdomain"],
                url=r["url"],
                scanned_at=r["scanned_at"],
                severity=r["severity"],
                template_id=r["template_id"],
                name=r["name"],
                matched_at=r["matched_at"],
            )
            for r in rows
        ]

    def _extract_katana_urls(self, program_id: int) -> list[KatanaUrl]:
        rows = self.conn.execute(
            "SELECT * FROM katana_results WHERE program_id = ? ORDER BY scanned_at DESC",
            (program_id,),
        ).fetchall()
        urls = []
        for r in rows:
            for url in r["urls"].split("\n"):
                url = url.strip()
                if url:
                    urls.append(
                        KatanaUrl(
                            id=r["id"],
                            subdomain=r["subdomain"],
                            scanned_at=r["scanned_at"],
                            url=url,
                        )
                    )
        return urls

    def _extract_js_files(self, program_id: int) -> list[JsFile]:
        rows = self.conn.execute(
            "SELECT * FROM js_files WHERE program_id = ? ORDER BY last_seen_at DESC",
            (program_id,),
        ).fetchall()
        return [
            JsFile(
                id=r["id"],
                url=r["url"],
                source_url=r["source_url"],
                current_hash=r["current_hash"],
                content_length=r["content_length"],
                first_seen_at=r["first_seen_at"],
                last_seen_at=r["last_seen_at"],
                last_changed_at=r["last_changed_at"],
                is_active=bool(r["is_active"]),
            )
            for r in rows
        ]

    def _extract_js_findings(self, program_id: int) -> list[JsFinding]:
        rows = self.conn.execute(
            """
            SELECT jf.* FROM js_findings jf
            WHERE jf.program_id = ?
            ORDER BY
                CASE jf.category
                    WHEN 'api_key' THEN 1
                    WHEN 'aws_key' THEN 2
                    WHEN 'aws_secret' THEN 3
                    WHEN 'google_api_key' THEN 4
                    WHEN 'credential' THEN 5
                    WHEN 'jwt' THEN 6
                    ELSE 7
                END,
                jf.last_seen_at DESC
            """,
            (program_id,),
        ).fetchall()
        return [
            JsFinding(
                id=r["id"],
                source_url=r["source_url"],
                source_type=r["source_type"],
                category=r["category"],
                value=r["value"],
                context=r["context"],
                first_seen_at=r["first_seen_at"],
                last_seen_at=r["last_seen_at"],
                is_active=bool(r["is_active"]),
            )
            for r in rows
        ]

    def _extract_asn_ranges(self, program_id: int) -> list[AsnRange]:
        rows = self.conn.execute(
            """
            SELECT ar.*, COUNT(ai.id) as ip_count
            FROM asn_ranges ar
            LEFT JOIN asn_ips ai ON ar.program_id = ai.program_id AND ar.cidr = ai.cidr
            WHERE ar.program_id = ?
            GROUP BY ar.id
            ORDER BY ar.discovered_at DESC
            """,
            (program_id,),
        ).fetchall()
        return [
            AsnRange(
                id=r["id"],
                asn=r["asn"],
                org=r["org"],
                cidr=r["cidr"],
                discovered_at=r["discovered_at"],
                ip_count=r["ip_count"],
            )
            for r in rows
        ]

    def _extract_asn_ips(self, program_id: int) -> list[AsnIp]:
        rows = self.conn.execute(
            "SELECT * FROM asn_ips WHERE program_id = ? ORDER BY alive DESC, ip",
            (program_id,),
        ).fetchall()
        return [
            AsnIp(
                id=r["id"],
                ip=r["ip"],
                cidr=r["cidr"],
                asn=r["asn"],
                alive=bool(r["alive"]),
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
            )
            for r in rows
        ]

    def _extract_run_history(self, program_id: int) -> list[RunHistory]:
        rows = self.conn.execute(
            "SELECT * FROM runs WHERE program_id = ? ORDER BY started_at DESC LIMIT 50",
            (program_id,),
        ).fetchall()
        return [
            RunHistory(
                id=r["id"],
                started_at=r["started_at"],
                finished_at=r["finished_at"],
                discovered=r["discovered"],
                new_subdomains=r["new_subdomains"],
                live_subdomains=r["live_subdomains"],
                nuclei_findings=r["nuclei_findings"],
                katana_urls=r["katana_urls"],
                js_files_found=r["js_files_found"],
                js_files_changed=r["js_files_changed"],
                js_findings_total=r["js_findings_total"],
                js_findings_new=r["js_findings_new"],
                js_findings_critical=r["js_findings_critical"],
                status=r["status"],
            )
            for r in rows
        ]


# =============================================================================
# JSON Export
# =============================================================================

def export_json(data: ExportData, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data.to_dict(), f, indent=2, ensure_ascii=False, default=str)
    print(f"[+] JSON exported: {output_path}")


# =============================================================================
# HTML Report Generator - FIXED VERSION
# =============================================================================

class HTMLReportGenerator:
    CRITICAL_JS_CATEGORIES = {"api_key", "aws_key", "aws_secret", "google_api_key", "credential", "jwt"}

    def __init__(self, data: ExportData):
        self.data = data
        self.summary = data.get_summary()

    def generate(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        html_content = self._build_html()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] HTML report exported: {output_path}")

    def _esc(self, s: Any) -> str:
        return escape(str(s) if s is not None else "")

    def _build_html(self) -> str:
        # Safely encode JSON to prevent any XSS or HTML parser breakage
        safe_json = json.dumps(self.data.to_dict(), default=str, ensure_ascii=False).replace("<", "\\u003c")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report - {self._esc(self.data.program.name)}</title>
    <style>{self._get_css()}</style>
</head>
<body>
    {self._render_header()}
    <main class="main-container">
        {self._render_summary_cards()}
        {self._render_tabs()}
        {self._render_filter_panel()}
        {self._render_tab_content()}
    </main>
    <script type="application/json" id="recon-data">
        {safe_json}
    </script>
    <script>{self._get_js()}</script>
</body>
</html>"""

    def _render_header(self) -> str:
        scope_tags = "".join(
            f'<span class="scope-tag">{self._esc(d)}</span>' 
            for d in self.data.program.scope_domains[:8]
        )
        more_count = len(self.data.program.scope_domains) - 8
        if more_count > 0:
            scope_tags += f'<span class="scope-tag scope-more">+{more_count} more</span>'
        
        return f"""
        <header class="header">
            <div class="header-inner">
                <div class="header-left">
                    <h1 class="header-title">🛡️ Recon Report</h1>
                    <div class="header-meta">
                        <span class="program-badge">{self._esc(self.data.program.name)}</span>
                        <span class="export-time">Exported: {self._esc(self.data.exported_at)}</span>
                    </div>
                </div>
                <div class="header-actions">
                    <button class="btn btn-outline" onclick="downloadJSON()">📄 JSON</button>
                </div>
            </div>
            <div class="scope-bar">
                <span class="scope-label">Scope:</span>
                {scope_tags}
            </div>
        </header>"""

    def _render_summary_cards(self) -> str:
        s = self.summary
        cards = [
            ("🌐", "Subdomains", s["total_subdomains"], f"✓ {s['alive_subdomains']} alive · ✗ {s['dead_subdomains']} dead", "#3b82f6"),
            ("🔗", "Unique URLs", s["unique_urls"], f"{len(self.data.httpx_results)} total probes", "#8b5cf6"),
            ("🚪", "Open Ports", s["unique_open_ports"], f"{s['total_ports']} hosts scanned", "#06b6d4"),
            ("⚡", "Vulns", s["nuclei_findings"], self._severity_summary(s["nuclei_by_severity"]), "#ef4444"),
            ("🕷️", "Katana URLs", s["unique_katana_urls"], f"{s['katana_urls']} total found", "#f59e0b"),
            ("📜", "JS Files", s["active_js_files"], f"{s['inactive_js_files']} inactive", "#10b981"),
            ("🔍", "JS Findings", s["js_findings"], f"⚠ {s['critical_js_findings']} critical", "#ec4899"),
            ("📡", "ASN IPs", s["alive_asn_ips"], f"{s['asn_ranges']} CIDR ranges", "#6366f1"),
        ]
        return f"""
        <section class="summary-section">
            <div class="summary-grid">
                {"".join(f'''
                <div class="summary-card" style="--card-accent: {color}">
                    <div class="card-icon">{icon}</div>
                    <div class="card-value">{value:,}</div>
                    <div class="card-label">{label}</div>
                    <div class="card-sub">{sub}</div>
                </div>''' for icon, label, value, sub, color in cards)}
            </div>
        </section>"""

    def _severity_summary(self, counts: dict[str, int]) -> str:
        parts = []
        for sev in ["critical", "high", "medium", "low"]:
            if counts.get(sev, 0) > 0:
                parts.append(f'<span class="mini-sev sev-{sev}">{counts[sev]}</span>')
        return " ".join(parts) if parts else "None"

    def _render_tabs(self) -> str:
        tabs = [
            ("subdomains", "Subdomains", len(self.data.subdomains)),
            ("urls", "URLs", len(self.data.httpx_results)),
            ("ports", "Ports", len(self.data.port_results)),
            ("vulns", "Vulns", len(self.data.nuclei_findings)),
            ("katana", "Katana", len(self.data.katana_urls)),
            ("jsfiles", "JS Files", len(self.data.js_files)),
            ("jsfindings", "JS Findings", len(self.data.js_findings)),
            ("asn", "ASN", len(self.data.asn_ips)),
            ("history", "History", len(self.data.run_history)),
        ]
        return f"""
        <nav class="tabs-nav">
            <div class="tabs-scroll">
                {"".join(f'<button class="tab-btn" data-tab="{tid}" onclick="switchTab(\'{tid}\')">{label} <span class="tab-badge">{count:,}</span></button>' for tid, label, count in tabs)}
            </div>
        </nav>"""

    def _render_filter_panel(self) -> str:
        status_codes = sorted(set(str(h.status_code) for h in self.data.httpx_results if h.status_code), key=lambda x: int(x) if x.isdigit() else 0)
        severities = ["critical", "high", "medium", "low", "info"]
        js_categories = sorted(set(jf.category for jf in self.data.js_findings))
        
        status_options = "".join(f'<option value="{self._esc(sc)}">{self._esc(sc)}</option>' for sc in status_codes[:30])
        severity_options = "".join(f'<option value="{sev}">{sev.upper()}</option>' for sev in severities)
        category_options = "".join(f'<option value="{self._esc(cat)}">{self._esc(cat)}</option>' for cat in js_categories[:20])
        
        return f"""
        <div class="filter-panel" id="filterPanel">
            <div class="filter-row">
                <div class="filter-group">
                    <label class="filter-label">🔍 Search</label>
                    <input type="text" class="filter-input" id="searchInput" placeholder="Type to filter..." oninput="applyFilters()">
                </div>
                <div class="filter-group filter-status" id="filterStatusGroup" style="display:none">
                    <label class="filter-label">Status</label>
                    <select class="filter-select" id="filterStatus" onchange="applyFilters()">
                        <option value="">All</option>
                        <option value="alive">Alive</option>
                        <option value="dead">Dead</option>
                    </select>
                </div>
                <div class="filter-group filter-severity" id="filterSeverityGroup" style="display:none">
                    <label class="filter-label">Severity</label>
                    <select class="filter-select" id="filterSeverity" onchange="applyFilters()">
                        <option value="">All</option>
                        {severity_options}
                    </select>
                </div>
                <div class="filter-group filter-statuscode" id="filterStatusCodeGroup" style="display:none">
                    <label class="filter-label">Status Code</label>
                    <select class="filter-select" id="filterStatusCode" onchange="applyFilters()">
                        <option value="">All</option>
                        {status_options}
                    </select>
                </div>
                <div class="filter-group filter-category" id="filterCategoryGroup" style="display:none">
                    <label class="filter-label">Category</label>
                    <select class="filter-select" id="filterCategory" onchange="applyFilters()">
                        <option value="">All</option>
                        {category_options}
                    </select>
                </div>
                <div class="filter-group filter-jsstatus" id="filterJsStatusGroup" style="display:none">
                    <label class="filter-label">JS Status</label>
                    <select class="filter-select" id="filterJsStatus" onchange="applyFilters()">
                        <option value="">All</option>
                        <option value="active">Active</option>
                        <option value="inactive">Inactive</option>
                    </select>
                </div>
                <div class="filter-actions">
                    <button class="btn btn-sm btn-secondary" onclick="clearFilters()">Clear</button>
                    <button class="btn btn-sm btn-primary" onclick="downloadCurrentCSV()">📥 CSV</button>
                    <button class="btn btn-sm btn-secondary" onclick="copySelected()">📋 Copy</button>
                </div>
            </div>
            <div class="filter-info" id="filterInfo">
                <span id="rowCount">0 rows</span>
                <div class="pagination-controls">
                    <button class="btn btn-sm btn-outline" onclick="prevPage()">Prev</button>
                    <span id="pageInfo">Page 1 of 1</span>
                    <button class="btn btn-sm btn-outline" onclick="nextPage()">Next</button>
                    <select class="filter-select" id="pageSize" onchange="changePageSize()" style="min-width: 80px; padding: 4px;">
                        <option value="50">50 / page</option>
                        <option value="100" selected>100 / page</option>
                        <option value="500">500 / page</option>
                        <option value="1000">1000 / page</option>
                    </select>
                </div>
                <label class="select-all">
                    <input type="checkbox" id="selectAll" onchange="toggleSelectAll(this.checked)">
                    Select All
                </label>
            </div>
        </div>"""

    def _render_tab_content(self) -> str:
        return f"""
        <section class="table-section">
            <div id="tab-subdomains" class="tab-pane active">{self._make_table("subdomains", ["", "Host", "Status", "Title", "Technology", "Ports", "Vulns", "Last Seen", ""])}</div>
            <div id="tab-urls" class="tab-pane">{self._make_table("urls", ["", "URL", "Code", "Method", "Title", "Tech", "Server", "IP", "CDN", "Scanned"])}</div>
            <div id="tab-ports" class="tab-pane">{self._make_table("ports", ["", "Subdomain", "Host", "IP", "Open Ports", "Scanned"])}</div>
            <div id="tab-vulns" class="tab-pane">{self._make_table("vulns", ["", "Severity", "Host", "URL", "Name", "Template", "Found"])}</div>
            <div id="tab-katana" class="tab-pane">{self._make_table("katana", ["", "URL", "Source", "Found"])}</div>
            <div id="tab-jsfiles" class="tab-pane">{self._make_table("jsfiles", ["", "URL", "Source", "Size", "Hash", "Status", "Last Seen", "Changed"])}</div>
            <div id="tab-jsfindings" class="tab-pane">{self._make_table("jsfindings", ["", "Category", "Value", "Type", "Source", "Context", "Status", "Last Seen"])}</div>
            <div id="tab-asn" class="tab-pane">{self._make_table("asn", ["", "IP", "ASN", "CIDR", "Status", "Last Seen"])}</div>
            <div id="tab-history" class="tab-pane">{self._make_table("history", ["Started", "Status", "Disc.", "New", "Live", "Vulns", "Katana", "JS Files", "JS Chg", "JS New", "JS Crit", "Finished"])}</div>
        </section>"""

    def _make_table(self, tab_id: str, headers: list[str]) -> str:
        th = "".join(f"<th>{h}</th>" for h in headers)
        return f"""
        <div class="table-wrap">
            <table>
                <thead><tr>{th}</tr></thead>
                <tbody id="tbody-{tab_id}"></tbody>
            </table>
        </div>"""

    def _get_css(self) -> str:
        return """
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        
        :root {
            --bg-base: #0a0e1a;
            --bg-surface: #111827;
            --bg-elevated: #1f2937;
            --bg-hover: #374151;
            --border: #1f2937;
            --border-light: #374151;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --green: #22c55e;
            --red: #ef4444;
            --orange: #f97316;
            --yellow: #eab308;
            --purple: #a855f7;
            --pink: #ec4899;
            --cyan: #06b6d4;
            --radius: 6px;
            --radius-lg: 10px;
        }
        
        html { font-size: 14px; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-base);
            color: var(--text-primary);
            line-height: 1.5;
            min-height: 100vh;
        }
        
        /* Header */
        .header {
            background: var(--bg-surface);
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .header-inner {
            max-width: 1800px;
            margin: 0 auto;
            padding: 16px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }
        .header-left { display: flex; flex-direction: column; gap: 6px; }
        .header-title { font-size: 1.4rem; font-weight: 700; }
        .header-meta { display: flex; align-items: center; gap: 12px; }
        .program-badge {
            background: linear-gradient(135deg, var(--accent), var(--purple));
            color: white;
            padding: 2px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9rem;
        }
        .export-time { color: var(--text-muted); font-size: 0.85rem; }
        .header-actions { display: flex; gap: 8px; }
        .scope-bar {
            max-width: 1800px;
            margin: 0 auto;
            padding: 8px 24px 12px;
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .scope-label { color: var(--text-muted); font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }
        .scope-tag {
            background: var(--bg-elevated);
            border: 1px solid var(--border-light);
            color: var(--text-secondary);
            padding: 2px 10px;
            border-radius: 4px;
            font-size: 0.78rem;
        }
        .scope-more { color: var(--text-muted); font-style: italic; }
        
        /* Main Container */
        .main-container {
            max-width: 1800px;
            margin: 0 auto;
            padding: 20px 24px;
        }
        
        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 20px;
        }
        .summary-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 16px;
            text-align: center;
            border-top: 3px solid var(--card-accent, var(--accent));
            transition: transform 0.15s ease;
        }
        .summary-card:hover { transform: translateY(-2px); }
        .card-icon { font-size: 1.3rem; margin-bottom: 6px; }
        .card-value { font-size: 1.8rem; font-weight: 800; line-height: 1.2; }
        .card-label { font-size: 0.85rem; color: var(--text-secondary); margin-top: 2px; }
        .card-sub { font-size: 0.75rem; color: var(--text-muted); margin-top: 8px; line-height: 1.4; }
        .mini-sev {
            display: inline-block;
            padding: 1px 6px;
            border-radius: 3px;
            font-size: 0.7rem;
            font-weight: 700;
            margin: 0 1px;
        }
        .mini-sev.sev-critical { background: rgba(239,68,68,0.3); color: #fca5a5; }
        .mini-sev.sev-high { background: rgba(249,115,22,0.3); color: #fdba74; }
        .mini-sev.sev-medium { background: rgba(234,179,8,0.3); color: #fde047; }
        .mini-sev.sev-low { background: rgba(59,130,246,0.3); color: #93c5fd; }
        
        /* Tabs */
        .tabs-nav {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg) var(--radius-lg) 0 0;
            overflow: hidden;
        }
        .tabs-scroll {
            display: flex;
            overflow-x: auto;
            scrollbar-width: none;
        }
        .tabs-scroll::-webkit-scrollbar { display: none; }
        .tab-btn {
            background: none;
            border: none;
            border-bottom: 2px solid transparent;
            color: var(--text-secondary);
            padding: 12px 20px;
            cursor: pointer;
            font-size: 0.9rem;
            white-space: nowrap;
            transition: all 0.15s ease;
        }
        .tab-btn:hover { color: var(--text-primary); background: var(--bg-elevated); }
        .tab-btn.active {
            color: var(--accent);
            border-bottom-color: var(--accent);
            background: var(--bg-elevated);
        }
        .tab-badge {
            background: var(--bg-base);
            padding: 1px 7px;
            border-radius: 10px;
            font-size: 0.75rem;
            margin-left: 6px;
        }
        .tab-btn.active .tab-badge { background: rgba(59,130,246,0.2); color: var(--accent); }
        
        /* Filter Panel */
        .filter-panel {
            background: var(--bg-surface);
            border-left: 1px solid var(--border);
            border-right: 1px solid var(--border);
            padding: 12px 16px;
        }
        .filter-row {
            display: flex;
            align-items: flex-end;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }
        .filter-group { display: flex; flex-direction: column; gap: 4px; }
        .filter-label { font-size: 0.75rem; color: var(--text-muted); font-weight: 600; text-transform: uppercase; }
        .filter-input, .filter-select {
            background: var(--bg-base);
            border: 1px solid var(--border-light);
            border-radius: var(--radius);
            padding: 7px 10px;
            color: var(--text-primary);
            font-size: 0.85rem;
            min-width: 160px;
        }
        .filter-input { min-width: 250px; flex: 1; max-width: 400px; }
        .filter-input:focus, .filter-select:focus { outline: none; border-color: var(--accent); }
        .filter-actions { display: flex; gap: 8px; margin-left: auto; align-items: flex-end; }
        .filter-info {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding-top: 8px;
            border-top: 1px solid var(--border);
            gap: 10px;
        }
        #rowCount { color: var(--text-muted); font-size: 0.8rem; min-width: 100px; }
        
        .pagination-controls { display: flex; align-items: center; gap: 8px; flex: 1; justify-content: center; }
        #pageInfo { font-size: 0.85rem; color: var(--text-secondary); min-width: 100px; text-align: center; }
        
        .select-all {
            display: flex;
            align-items: center;
            gap: 6px;
            color: var(--text-secondary);
            font-size: 0.8rem;
            cursor: pointer;
            min-width: 100px;
            justify-content: flex-end;
        }
        
        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 7px 14px;
            border-radius: var(--radius);
            border: 1px solid transparent;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.15s ease;
            white-space: nowrap;
        }
        .btn-primary { background: var(--accent); color: white; border-color: var(--accent); }
        .btn-primary:hover { background: var(--accent-hover); }
        .btn-secondary { background: var(--bg-elevated); color: var(--text-primary); border-color: var(--border-light); }
        .btn-secondary:hover { background: var(--bg-hover); }
        .btn-outline { background: transparent; color: var(--text-secondary); border-color: var(--border-light); }
        .btn-outline:hover { background: var(--bg-elevated); color: var(--text-primary); }
        .btn-sm { padding: 5px 10px; font-size: 0.8rem; }
        
        /* Table Section */
        .table-section {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-top: none;
            border-radius: 0 0 var(--radius-lg) var(--radius-lg);
            overflow: hidden;
        }
        .tab-pane { display: none; }
        .tab-pane.active { display: block; }
        
        .table-wrap {
            overflow-x: auto;
            max-height: calc(100vh - 380px);
            overflow-y: auto;
        }
        .table-wrap::-webkit-scrollbar { width: 8px; height: 8px; }
        .table-wrap::-webkit-scrollbar-track { background: var(--bg-surface); }
        .table-wrap::-webkit-scrollbar-thumb { background: var(--bg-hover); border-radius: 4px; }
        .table-wrap::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.82rem;
        }
        thead { position: sticky; top: 0; z-index: 10; }
        th {
            background: var(--bg-elevated);
            color: var(--text-secondary);
            font-weight: 600;
            text-align: left;
            padding: 10px 12px;
            border-bottom: 2px solid var(--border);
            white-space: nowrap;
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }
        td {
            padding: 8px 12px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }
        tr:hover td { background: rgba(59,130,246,0.04); }
        tr.row-hidden { display: none; }
        tr.row-inactive { opacity: 0.55; }
        tr.row-critical { background: rgba(239,68,68,0.06); }
        tr.vuln-row-critical { border-left: 3px solid var(--red); }
        tr.vuln-row-high { border-left: 3px solid var(--orange); }
        
        /* Cell Types */
        .td-check { width: 36px; text-align: center; }
        .td-host, .td-url, .td-ip { min-width: 200px; }
        .td-status { width: 90px; }
        .td-title { max-width: 200px; }
        .td-tech { max-width: 180px; }
        .td-ports { min-width: 150px; }
        .td-vulns { width: 50px; text-align: center; }
        .td-date { width: 100px; white-space: nowrap; color: var(--text-muted); }
        .td-link { width: 30px; text-align: center; }
        .td-method { width: 60px; }
        .td-server { width: 80px; }
        .td-cdn { width: 80px; }
        .td-severity { width: 80px; }
        .td-name { max-width: 250px; }
        .td-template { max-width: 150px; }
        .td-size { width: 70px; text-align: right; }
        .td-hash { width: 100px; }
        .td-category { width: 100px; }
        .td-value { max-width: 300px; }
        .td-type { width: 80px; }
        .td-context { max-width: 200px; font-style: italic; color: var(--text-muted); }
        .td-asn, .td-cidr { width: 120px; }
        .td-num { text-align: right; font-variant-numeric: tabular-nums; }
        .td-vuln-highlight { color: #fca5a5; font-weight: 600; }
        .td-crit-highlight { color: #fca5a5; font-weight: 700; }
        
        /* Text Styles */
        .mono-text { font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace; font-size: 0.8rem; }
        .text-ellipsis { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: block; }
        
        /* Status Pills */
        .status-pill {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-align: center;
            min-width: 45px;
        }
        .status-alive, .status-2xx, .status-active, .status-ok { background: rgba(34,197,94,0.15); color: #86efac; }
        .status-dead, .status-5xx, .status-inactive, .status-error { background: rgba(239,68,68,0.15); color: #fca5a5; }
        .status-3xx { background: rgba(59,130,246,0.15); color: #93c5fd; }
        .status-4xx { background: rgba(249,115,22,0.15); color: #fdba74; }
        .status-running { background: rgba(234,179,8,0.15); color: #fde047; }
        
        /* Severity Pills */
        .sev-pill {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.5px;
        }
        .sev-critical { background: rgba(239,68,68,0.2); color: #fca5a5; border: 1px solid rgba(239,68,68,0.4); }
        .sev-high { background: rgba(249,115,22,0.2); color: #fdba74; border: 1px solid rgba(249,115,22,0.4); }
        .sev-medium { background: rgba(234,179,8,0.2); color: #fde047; border: 1px solid rgba(234,179,8,0.4); }
        .sev-low { background: rgba(59,130,246,0.2); color: #93c5fd; border: 1px solid rgba(59,130,246,0.4); }
        .sev-info, .sev-unknown { background: rgba(107,114,128,0.2); color: #d1d5db; border: 1px solid rgba(107,114,128,0.4); }
        
        /* Port Tags */
        .port-tag {
            display: inline-block;
            background: var(--bg-base);
            border: 1px solid var(--border-light);
            padding: 1px 6px;
            border-radius: 3px;
            font-size: 0.72rem;
            font-family: monospace;
            margin: 1px;
        }
        .port-more { color: var(--text-muted); font-style: italic; border-style: dashed; }
        .port-list { display: flex; flex-wrap: wrap; gap: 2px; }
        
        /* Vuln/CDN Tags */
        .vuln-badge {
            background: rgba(239,68,68,0.2);
            color: #fca5a5;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.8rem;
        }
        .cdn-tag {
            background: rgba(168,85,247,0.2);
            color: #d8b4fe;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.72rem;
        }
        .cat-pill {
            display: inline-block;
            background: var(--bg-base);
            border: 1px solid var(--border-light);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 500;
        }
        .cat-critical {
            background: rgba(239,68,68,0.2);
            color: #fca5a5;
            border-color: rgba(239,68,68,0.4);
            font-weight: 700;
        }
        
        .ext-link {
            color: var(--accent);
            text-decoration: none;
            font-size: 1.1rem;
        }
        .ext-link:hover { color: var(--accent-hover); }
        
        /* Checkbox */
        input[type="checkbox"] {
            width: 14px;
            height: 14px;
            cursor: pointer;
            accent-color: var(--accent);
        }
        
        /* Responsive */
        @media (max-width: 1024px) {
            .main-container { padding: 16px; }
            .summary-grid { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }
            .filter-row { flex-direction: column; align-items: stretch; }
            .filter-input { max-width: 100%; min-width: 100%; }
            .filter-actions { margin-left: 0; }
            .td-host, .td-url { min-width: 150px; }
        }
        @media (max-width: 640px) {
            .header-inner { padding: 12px 16px; }
            .header-title { font-size: 1.1rem; }
            .scope-bar { padding: 8px 16px 10px; }
            .main-container { padding: 12px; }
            .summary-grid { grid-template-columns: repeat(2, 1fr); gap: 8px; }
            .summary-card { padding: 12px; }
            .card-value { font-size: 1.4rem; }
            .tab-btn { padding: 10px 14px; font-size: 0.82rem; }
            .pagination-controls { flex-wrap: wrap; }
        }
        """

    def _get_js(self) -> str:
        return f"""
        const DATA = JSON.parse(document.getElementById('recon-data').textContent);
        let currentTab = 'subdomains';
        let currentPage = 1;
        let pageSize = 100;
        let filteredData = [];
        
        // Escape HTML to prevent XSS
        function esc(str) {{
            if (str === null || str === undefined) return '';
            return String(str).replace(/[&<>'"]/g, 
                tag => ({{
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    "'": '&#39;',
                    '"': '&quot;'
                }}[tag] || tag));
        }}

        // Tab switching
        function switchTab(tabId) {{
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            document.querySelector(`[data-tab="${{tabId}}"]`).classList.add('active');
            document.getElementById(`tab-${{tabId}}`).classList.add('active');
            currentTab = tabId;
            currentPage = 1;
            updateFilterVisibility();
            applyFilters();
        }}
        
        // Show/hide relevant filters
        function updateFilterVisibility() {{
            const groups = {{
                'subdomains': ['filterStatusGroup'],
                'urls': ['filterStatusCodeGroup'],
                'vulns': ['filterSeverityGroup'],
                'jsfiles': ['filterJsStatusGroup'],
                'jsfindings': ['filterCategoryGroup', 'filterJsStatusGroup'],
                'asn': ['filterStatusGroup'],
            }};
            const allGroups = ['filterStatusGroup', 'filterSeverityGroup', 'filterStatusCodeGroup', 'filterCategoryGroup', 'filterJsStatusGroup'];
            allGroups.forEach(id => {{
                const el = document.getElementById(id);
                if (el) el.style.display = 'none';
            }});
            (groups[currentTab] || []).forEach(id => {{
                const el = document.getElementById(id);
                if (el) el.style.display = 'flex';
            }});
        }}
        
        // Apply all filters on the data array directly
        function applyFilters() {{
            const search = document.getElementById('searchInput').value.toLowerCase().trim();
            const status = getFilterVal('filterStatus');
            const severity = getFilterVal('filterSeverity');
            const statusCode = getFilterVal('filterStatusCode');
            const category = getFilterVal('filterCategory');
            const jsStatus = getFilterVal('filterJsStatus');
            
            let dataset = [];
            if (currentTab === 'subdomains') dataset = DATA.subdomains;
            else if (currentTab === 'urls') dataset = DATA.httpx_results;
            else if (currentTab === 'ports') dataset = DATA.port_results;
            else if (currentTab === 'vulns') dataset = DATA.nuclei_findings;
            else if (currentTab === 'katana') dataset = DATA.katana_urls;
            else if (currentTab === 'jsfiles') dataset = DATA.js_files;
            else if (currentTab === 'jsfindings') dataset = DATA.js_findings;
            else if (currentTab === 'asn') dataset = DATA.asn_ips;
            else if (currentTab === 'history') dataset = DATA.run_history;

            filteredData = dataset.filter(row => {{
                // Quick global text search on values
                if (search) {{
                    const rowText = Object.values(row).join(' ').toLowerCase();
                    if (!rowText.includes(search)) return false;
                }}
                
                // Status filter (subdomains, asn)
                if (status) {{
                    const isAlive = row.alive === true;
                    if (status === 'alive' && !isAlive) return false;
                    if (status === 'dead' && isAlive) return false;
                }}
                
                // Severity filter (vulns)
                if (severity && row.severity) {{
                    if ((row.severity||'').toLowerCase() !== severity) return false;
                }}
                
                // Status code filter (urls)
                if (statusCode && row.status_code) {{
                    if (String(row.status_code) !== statusCode) return false;
                }}
                
                // Category filter (js findings)
                if (category && row.category) {{
                    if (row.category !== category) return false;
                }}
                
                // JS status filter
                if (jsStatus && row.is_active !== undefined) {{
                    const isActive = row.is_active === true;
                    if (jsStatus === 'active' && !isActive) return false;
                    if (jsStatus === 'inactive' && isActive) return false;
                }}
                
                return true;
            }});

            currentPage = 1;
            renderTable();
        }}
        
        function renderTable() {{
            const tbody = document.getElementById(`tbody-${{currentTab}}`);
            if (!tbody) return;
            
            const totalRows = filteredData.length;
            const totalPages = Math.ceil(totalRows / pageSize) || 1;
            if (currentPage > totalPages) currentPage = totalPages;
            
            const startIdx = (currentPage - 1) * pageSize;
            const endIdx = Math.min(startIdx + pageSize, totalRows);
            const pageData = filteredData.slice(startIdx, endIdx);
            
            let html = '';
            
            pageData.forEach(row => {{
                if (currentTab === 'subdomains') {{
                    const statusStr = row.http_status ? String(row.http_status) : (row.alive ? "ALIVE" : "DEAD");
                    let statusClass = row.alive ? "status-alive" : "status-dead";
                    if (row.http_status) {{
                        if (row.http_status < 300) statusClass = "status-2xx";
                        else if (row.http_status < 400) statusClass = "status-3xx";
                        else if (row.http_status < 500) statusClass = "status-4xx";
                        else statusClass = "status-5xx";
                    }}
                    let portsHtml = (row.ports || []).slice(0, 4).map(p => `<span class="port-tag">${{esc(p)}}</span>`).join('');
                    if ((row.ports || []).length > 4) portsHtml += `<span class="port-tag port-more">+${{row.ports.length - 4}}</span>`;
                    const vulnsHtml = row.nuclei_count ? `<span class="vuln-badge">${{row.nuclei_count}}</span>` : '—';
                    const linkHtml = row.http_url ? `<a href="${{esc(row.http_url)}}" target="_blank" class="ext-link" title="${{esc(row.http_url)}}">↗</a>` : '';
                    
                    html += `<tr data-status="${{row.alive ? 'alive' : 'dead'}}">
                        <td class="td-check"><input type="checkbox" class="row-cb" value="${{esc(row.host)}}"></td>
                        <td class="td-host"><span class="mono-text">${{esc(row.host)}}</span></td>
                        <td class="td-status"><span class="status-pill ${{statusClass}}">${{esc(statusStr)}}</span></td>
                        <td class="td-title" title="${{esc(row.http_title)}}">${{esc((row.http_title||'').substring(0,50)) || (row.http_title ? '' : '—')}}</td>
                        <td class="td-tech" title="${{esc(row.http_tech)}}">${{esc((row.http_tech||'').substring(0,40)) || (row.http_tech ? '' : '—')}}</td>
                        <td class="td-ports">${{portsHtml || '—'}}</td>
                        <td class="td-vulns">${{vulnsHtml}}</td>
                        <td class="td-date">${{esc((row.last_seen||'').substring(0,10))}}</td>
                        <td class="td-link">${{linkHtml}}</td>
                    </tr>`;
                }}
                else if (currentTab === 'urls') {{
                    const sc = row.status_code ? String(row.status_code) : "—";
                    let scClass = "status-dead";
                    if (row.status_code) {{
                        if (row.status_code < 300) scClass = "status-2xx";
                        else if (row.status_code < 400) scClass = "status-3xx";
                        else if (row.status_code < 500) scClass = "status-4xx";
                        else scClass = "status-5xx";
                    }}
                    const cdnHtml = row.cdn_name ? `<span class="cdn-tag">${{esc(row.cdn_name)}}</span>` : '—';
                    html += `<tr>
                        <td class="td-check"><input type="checkbox" class="row-cb" value="${{esc(row.url)}}"></td>
                        <td class="td-url"><span class="mono-text text-ellipsis" title="${{esc(row.url)}}">${{esc(row.url) || '—'}}</span></td>
                        <td class="td-status"><span class="status-pill ${{scClass}}">${{esc(sc)}}</span></td>
                        <td class="td-method">${{esc(row.method) || '—'}}</td>
                        <td class="td-title text-ellipsis" title="${{esc(row.title)}}">${{esc(row.title) || '—'}}</td>
                        <td class="td-tech text-ellipsis" title="${{esc(row.tech)}}">${{esc((row.tech||'').substring(0,40)) || '—'}}</td>
                        <td class="td-server">${{esc(row.webserver) || '—'}}</td>
                        <td class="td-ip"><span class="mono-text">${{esc(row.host_ip) || '—'}}</span></td>
                        <td class="td-cdn">${{cdnHtml}}</td>
                        <td class="td-date">${{esc((row.scanned_at||'').substring(0,10))}}</td>
                    </tr>`;
                }}
                else if (currentTab === 'ports') {{
                    const ports = (row.open_ports || '').split(',');
                    let portTags = ports.slice(0, 8).map(p => `<span class="port-tag">${{esc(p.trim())}}</span>`).join('');
                    if (ports.length > 8) portTags += `<span class="port-tag port-more">+${{ports.length - 8}}</span>`;
                    html += `<tr>
                        <td class="td-check"><input type="checkbox" class="row-cb" value="${{esc(row.subdomain)}}"></td>
                        <td class="td-host"><span class="mono-text">${{esc(row.subdomain)}}</span></td>
                        <td class="td-host"><span class="mono-text">${{esc(row.host || row.subdomain)}}</span></td>
                        <td class="td-ip"><span class="mono-text">${{esc(row.ip) || '—'}}</span></td>
                        <td class="td-ports"><div class="port-list">${{portTags}}</div></td>
                        <td class="td-date">${{esc((row.scanned_at||'').substring(0,10))}}</td>
                    </tr>`;
                }}
                else if (currentTab === 'vulns') {{
                    const sev = (row.severity || 'unknown').toLowerCase();
                    html += `<tr class="vuln-row-${{sev}}">
                        <td class="td-check"><input type="checkbox" class="row-cb" value="${{esc(row.url || row.subdomain)}}"></td>
                        <td class="td-severity"><span class="sev-pill sev-${{sev}}">${{esc((row.severity || 'unknown').toUpperCase())}}</span></td>
                        <td class="td-host"><span class="mono-text text-ellipsis">${{esc(row.subdomain)}}</span></td>
                        <td class="td-url"><span class="mono-text text-ellipsis" title="${{esc(row.url)}}">${{esc(row.url) || '—'}}</span></td>
                        <td class="td-name text-ellipsis" title="${{esc(row.name)}}">${{esc(row.name) || '—'}}</td>
                        <td class="td-template"><span class="mono-text text-ellipsis">${{esc(row.template_id) || '—'}}</span></td>
                        <td class="td-date">${{esc((row.scanned_at||'').substring(0,10))}}</td>
                    </tr>`;
                }}
                else if (currentTab === 'katana') {{
                    html += `<tr>
                        <td class="td-check"><input type="checkbox" class="row-cb" value="${{esc(row.url)}}"></td>
                        <td class="td-url"><span class="mono-text text-ellipsis" title="${{esc(row.url)}}">${{esc(row.url)}}</span></td>
                        <td class="td-host"><span class="mono-text">${{esc(row.subdomain)}}</span></td>
                        <td class="td-date">${{esc((row.scanned_at||'').substring(0,10))}}</td>
                    </tr>`;
                }}
                else if (currentTab === 'jsfiles') {{
                    const activeClass = row.is_active ? 'row-active' : 'row-inactive';
                    const pillClass = row.is_active ? 'status-active' : 'status-inactive';
                    const pillText = row.is_active ? 'Active' : 'Inactive';
                    html += `<tr class="${{activeClass}}">
                        <td class="td-check"><input type="checkbox" class="row-cb" value="${{esc(row.url)}}"></td>
                        <td class="td-url"><span class="mono-text text-ellipsis" title="${{esc(row.url)}}">${{esc(row.url)}}</span></td>
                        <td class="td-url"><span class="mono-text text-ellipsis" title="${{esc(row.source_url)}}">${{esc(row.source_url) || '—'}}</span></td>
                        <td class="td-size">${{row.content_length || '—'}}</td>
                        <td class="td-hash"><span class="mono-text">${{esc((row.current_hash || '').substring(0,10))}}…</span></td>
                        <td class="td-status"><span class="status-pill ${{pillClass}}">${{pillText}}</span></td>
                        <td class="td-date">${{esc((row.last_seen_at||'').substring(0,10))}}</td>
                        <td class="td-date">${{esc(((row.last_changed_at || row.first_seen_at)||'').substring(0,10))}}</td>
                    </tr>`;
                }}
                else if (currentTab === 'jsfindings') {{
                    const criticalCategories = ['api_key', 'aws_key', 'aws_secret', 'google_api_key', 'credential', 'jwt'];
                    const isCrit = criticalCategories.includes(row.category);
                    let rowClass = isCrit ? 'row-critical ' : '';
                    rowClass += !row.is_active ? 'row-inactive' : '';
                    const valueDisp = row.value.length > 80 ? row.value.substring(0,80) + '…' : row.value;
                    const pillClass = row.is_active ? 'status-active' : 'status-inactive';
                    const pillText = row.is_active ? 'Active' : 'Old';
                    html += `<tr class="${{rowClass}}">
                        <td class="td-check"><input type="checkbox" class="row-cb" value="${{esc(row.value)}}"></td>
                        <td class="td-category"><span class="cat-pill ${{isCrit ? 'cat-critical' : ''}}">${{esc(row.category)}}</span></td>
                        <td class="td-value text-ellipsis" title="${{esc(row.value)}}">${{esc(valueDisp)}}</td>
                        <td class="td-type">${{esc(row.source_type)}}</td>
                        <td class="td-url"><span class="mono-text text-ellipsis" title="${{esc(row.source_url)}}">${{esc(row.source_url) || '—'}}</span></td>
                        <td class="td-context text-ellipsis" title="${{esc(row.context)}}">${{esc((row.context||'').substring(0,50)) || (row.context ? '' : '—')}}</td>
                        <td class="td-status"><span class="status-pill ${{pillClass}}">${{pillText}}</span></td>
                        <td class="td-date">${{esc((row.last_seen_at||'').substring(0,10))}}</td>
                    </tr>`;
                }}
                else if (currentTab === 'asn') {{
                    const rowClass = row.alive ? 'row-active' : 'row-inactive';
                    const pillClass = row.alive ? 'status-alive' : 'status-dead';
                    const pillText = row.alive ? 'Alive' : 'Dead';
                    html += `<tr class="${{rowClass}}">
                        <td class="td-check"><input type="checkbox" class="row-cb" value="${{esc(row.ip)}}"></td>
                        <td class="td-ip"><span class="mono-text">${{esc(row.ip)}}</span></td>
                        <td class="td-asn"><span class="mono-text">${{esc(row.asn) || '—'}}</span></td>
                        <td class="td-cidr"><span class="mono-text">${{esc(row.cidr) || '—'}}</span></td>
                        <td class="td-status"><span class="status-pill ${{pillClass}}">${{pillText}}</span></td>
                        <td class="td-date">${{esc((row.last_seen||'').substring(0,10))}}</td>
                    </tr>`;
                }}
                else if (currentTab === 'history') {{
                    const statusClass = row.status === 'ok' ? 'status-ok' : (row.status === 'running' ? 'status-running' : 'status-error');
                    html += `<tr>
                        <td class="td-date">${{esc((row.started_at||'').substring(0,19).replace('T', ' '))}}</td>
                        <td class="td-status"><span class="status-pill ${{statusClass}}">${{esc(row.status)}}</span></td>
                        <td class="td-num">${{row.discovered}}</td>
                        <td class="td-num">${{row.new_subdomains}}</td>
                        <td class="td-num">${{row.live_subdomains}}</td>
                        <td class="td-num td-vuln-highlight">${{row.nuclei_findings}}</td>
                        <td class="td-num">${{row.katana_urls}}</td>
                        <td class="td-num">${{row.js_files_found}}</td>
                        <td class="td-num">${{row.js_files_changed}}</td>
                        <td class="td-num">${{row.js_findings_new}}</td>
                        <td class="td-num td-crit-highlight">${{row.js_findings_critical}}</td>
                        <td class="td-date">${{esc((row.finished_at||'—').substring(0,19).replace('T', ' '))}}</td>
                    </tr>`;
                }}
            }});
            
            tbody.innerHTML = html;
            
            document.getElementById('rowCount').textContent = `${{totalRows.toLocaleString()}} rows`;
            document.getElementById('pageInfo').textContent = `Page ${{currentPage}} of ${{totalPages}}`;
            document.getElementById('selectAll').checked = false;
        }}
        
        function changePageSize() {{
            pageSize = parseInt(document.getElementById('pageSize').value, 10);
            currentPage = 1;
            renderTable();
        }}
        
        function prevPage() {{
            if (currentPage > 1) {{
                currentPage--;
                renderTable();
            }}
        }}
        
        function nextPage() {{
            const totalPages = Math.ceil(filteredData.length / pageSize) || 1;
            if (currentPage < totalPages) {{
                currentPage++;
                renderTable();
            }}
        }}
        
        function getFilterVal(id) {{
            const el = document.getElementById(id);
            return el ? el.value : '';
        }}
        
        function clearFilters() {{
            document.getElementById('searchInput').value = '';
            document.querySelectorAll('.filter-select').forEach(s => s.value = '');
            if(document.getElementById('pageSize')) document.getElementById('pageSize').value = pageSize;
            applyFilters();
        }}
        
        // Selection
        function toggleSelectAll(checked) {{
            const table = document.querySelector(`#tab-${{currentTab}} table`);
            if (!table) return;
            table.querySelectorAll('.row-cb').forEach(cb => {{
                cb.checked = checked;
            }});
        }}
        
        function getSelected() {{
            const table = document.querySelector(`#tab-${{currentTab}} table`);
            if (!table) return [];
            return Array.from(table.querySelectorAll('.row-cb:checked')).map(cb => cb.value).filter(Boolean);
        }}
        
        function copySelected() {{
            const vals = getSelected();
            if (!vals.length) {{ alert('No rows selected on this page'); return; }}
            navigator.clipboard.writeText(vals.join('\\n')).then(() => alert(`Copied ${{vals.length}} items`));
        }}
        
        // Download functions
        function downloadCurrentCSV() {{
            if (!filteredData.length) return;
            
            const table = document.querySelector(`#tab-${{currentTab}} table`);
            const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent.trim()).filter(h => h);
            
            // Generate rows from filteredData, not just the visible page
            let csvRows = [];
            filteredData.forEach(row => {{
                let vals = [];
                if (currentTab === 'subdomains') {{
                    vals = [row.host, row.alive?'ALIVE':'DEAD', row.http_title, row.http_tech, (row.ports||[]).join(';'), row.nuclei_count, row.last_seen];
                }} else if (currentTab === 'urls') {{
                    vals = [row.url, row.status_code, row.method, row.title, row.tech, row.webserver, row.host_ip, row.cdn_name, row.scanned_at];
                }} else if (currentTab === 'ports') {{
                    vals = [row.subdomain, row.host||row.subdomain, row.ip, row.open_ports, row.scanned_at];
                }} else if (currentTab === 'vulns') {{
                    vals = [row.severity, row.subdomain, row.url, row.name, row.template_id, row.scanned_at];
                }} else if (currentTab === 'katana') {{
                    vals = [row.url, row.subdomain, row.scanned_at];
                }} else if (currentTab === 'jsfiles') {{
                    vals = [row.url, row.source_url, row.content_length, row.current_hash, row.is_active?'Active':'Inactive', row.last_seen_at, row.last_changed_at];
                }} else if (currentTab === 'jsfindings') {{
                    vals = [row.category, row.value, row.source_type, row.source_url, row.context, row.is_active?'Active':'Old', row.last_seen_at];
                }} else if (currentTab === 'asn') {{
                    vals = [row.ip, row.asn, row.cidr, row.alive?'Alive':'Dead', row.last_seen];
                }} else if (currentTab === 'history') {{
                    vals = [row.started_at, row.status, row.discovered, row.new_subdomains, row.live_subdomains, row.nuclei_findings, row.katana_urls, row.js_files_found, row.js_files_changed, row.js_findings_new, row.js_findings_critical, row.finished_at];
                }} else {{
                    vals = Object.values(row);
                }}
                csvRows.push(vals.map(v => '"' + String(v||'').replace(/"/g, '""') + '"').join(','));
            }});
            
            downloadFile([headers.join(','), ...csvRows].join('\\n'), `recon_${{currentTab}}.csv`, 'text/csv');
        }}
        
        function downloadJSON() {{
            downloadFile(JSON.stringify(DATA, null, 2), `recon_${{DATA.program.name}}.json`, 'application/json');
        }}
        
        function downloadFile(content, name, type) {{
            const blob = new Blob([content], {{ type }});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = name;
            a.click();
            URL.revokeObjectURL(a.href);
        }}
        
        // Keyboard shortcuts
        document.addEventListener('keydown', e => {{
            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {{
                e.preventDefault();
                document.getElementById('searchInput').focus();
            }}
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {{
                e.preventDefault();
                downloadJSON();
            }}
            if (e.key === 'Escape') {{
                clearFilters();
                document.getElementById('searchInput').blur();
            }}
        }});
        
        // Init
        updateFilterVisibility();
        applyFilters();
        """

# =============================================================================
# Multi-Program Export
# =============================================================================

def export_all_programs(
    db_path: Path,
    output_dir: Path,
    severity_filter: Optional[list[str]] = None,
    format_type: str = "both"
) -> None:
    extractor = DatabaseExtractor(db_path)
    try:
        extractor.connect()
        programs = extractor.list_programs()

        if not programs:
            print("[!] No programs found in database")
            return

        print(f"[*] Found {len(programs)} programs to export")

        for prog in programs:
            if not prog["enabled"]:
                print(f"    - Skipping disabled: {prog['name']}")
                continue

            print(f"\n[*] Exporting: {prog['name']}")
            try:
                data = extractor.extract_program(prog["id"], severity_filter)
                program_dir = output_dir / prog["name"]

                if format_type in ("json", "both"):
                    export_json(data, program_dir / f"{prog['name']}_report.json")

                if format_type in ("html", "both"):
                    generator = HTMLReportGenerator(data)
                    generator.generate(program_dir / f"{prog['name']}_report.html")

            except Exception as e:
                print(f"[!] Error: {e}")

        _generate_index(output_dir, programs, extractor)

    finally:
        extractor.close()


def _generate_index(output_dir: Path, programs: list[dict], extractor: DatabaseExtractor) -> None:
    cards = []
    for prog in programs:
        if not prog["enabled"]:
            continue
        stats = extractor._get_program_stats(prog["id"])
        cards.append(f"""
        <div class="prog-card">
            <h3>{escape(prog['name'])}</h3>
            <div class="prog-stats">
                <div class="prog-stat"><span class="prog-val">{stats.get('subdomains', 0):,}</span><span class="prog-lbl">Subs</span></div>
                <div class="prog-stat"><span class="prog-val">{stats.get('nuclei_findings', 0):,}</span><span class="prog-lbl">Vulns</span></div>
                <div class="prog-stat"><span class="prog-val">{stats.get('katana_results', 0):,}</span><span class="prog-lbl">Katana</span></div>
                <div class="prog-stat"><span class="prog-val">{stats.get('js_findings', 0):,}</span><span class="prog-lbl">JS</span></div>
            </div>
            <div class="prog-links">
                <a href="{escape(prog['name'])}/{escape(prog['name'])}_report.html" class="btn btn-primary btn-sm">HTML</a>
                <a href="{escape(prog['name'])}/{escape(prog['name'])}_report.json" class="btn btn-secondary btn-sm">JSON</a>
            </div>
        </div>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Reports</title>
    <style>
        :root {{ --bg: #0a0e1a; --bg2: #111827; --bg3: #1f2937; --text: #f9fafb; --text2: #9ca3af; --accent: #3b82f6; --border: #1f2937; }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 24px; }}
        h1 {{ text-align: center; margin-bottom: 40px; font-size: 2rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; }}
        .prog-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 24px; }}
        .prog-card h3 {{ color: var(--accent); margin-bottom: 16px; }}
        .prog-stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 16px; }}
        .prog-stat {{ text-align: center; }}
        .prog-val {{ display: block; font-size: 1.3rem; font-weight: 700; }}
        .prog-lbl {{ font-size: 0.75rem; color: var(--text2); }}
        .prog-links {{ display: flex; gap: 8px; }}
        .btn {{ padding: 6px 14px; border-radius: 5px; text-decoration: none; font-size: 0.85rem; font-weight: 500; }}
        .btn-primary {{ background: var(--accent); color: white; }}
        .btn-secondary {{ background: var(--bg3); color: var(--text); }}
        .btn-sm {{ padding: 5px 12px; font-size: 0.8rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Recon Reports</h1>
        <div class="grid">{"".join(cards)}</div>
    </div>
</body>
</html>"""

    (output_dir / "index.html").write_text(html, encoding="utf-8")
    print(f"\n[+] Index: {output_dir / 'index.html'}")


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export recon data to HTML/JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--db", "-d", type=Path, required=True, help="Path to recon.db")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--program", "-p", type=str, help="Program name")
    mode.add_argument("--all-programs", "-a", action="store_true", help="Export all")
    mode.add_argument("--list-programs", "-l", action="store_true", help="List programs")

    parser.add_argument("--output", "-o", type=Path, default=None, help="Output directory")
    parser.add_argument("--format", "-f", choices=["html", "json", "both"], default="both")
    parser.add_argument("--severities", "-s", type=str, default=None, help="Severity filter")
    parser.add_argument("--quiet", "-q", action="store_true")

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.db.exists():
        print(f"[!] Database not found: {args.db}", file=sys.stderr)
        return 1

    extractor = DatabaseExtractor(args.db)
    try:
        extractor.connect()

        if args.list_programs:
            programs = extractor.list_programs()
            if not programs:
                print("[!] No programs found")
                return 1
            print(f"\n{'ID':<5} {'Status':<10} {'Last Scan':<22} {'Program'}")
            print("-" * 60)
            for p in programs:
                status = "✓ enabled" if p["enabled"] else "✗ disabled"
                last = (p["last_scanned_at"] or "Never")[:19].replace("T", " ")
                print(f"{p['id']:<5} {status:<10} {last:<22} {p['name']}")
            return 0

        severity_filter = None
        if args.severities:
            severity_filter = [s.strip().lower() for s in args.severities.split(",")]

        if args.all_programs:
            output_dir = args.output or args.db.parent / "exports"
            export_all_programs(args.db, output_dir, severity_filter, args.format)
            return 0

        if args.program:
            program_id = extractor.get_program_id(args.program)
            if not program_id:
                print(f"[!] Program not found: {args.program}", file=sys.stderr)
                return 1

            output_dir = args.output or args.db.parent / "exports" / args.program
            data = extractor.extract_program(program_id, severity_filter)

            if args.format in ("json", "both"):
                export_json(data, output_dir / f"{args.program}_report.json")
            if args.format in ("html", "both"):
                HTMLReportGenerator(data).generate(output_dir / f"{args.program}_report.html")

            if not args.quiet:
                print(f"\n[+] Done! Output: {output_dir}")
            return 0

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1
    finally:
        extractor.close()


if __name__ == "__main__":
    sys.exit(main())