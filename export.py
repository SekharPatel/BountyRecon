#!/usr/bin/env python3
"""
export.py

Export tool for bugBounty_auto_recon database.
Generates interactive HTML reports and JSON exports with filtering capabilities.

Usage:
    python export.py --db /path/to/recon.db --program "company_1"
    python export.py --db /path/to/recon.db --all-programs --output ./reports
    python export.py --db /path/to/recon.db --list-programs
    python export.py --db /path/to/recon.db --program "company_1" --format json
    python export.py --db /path/to/recon.db --program "company_1" --severities critical,high
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
import hashlib


# =============================================================================
# Data Models
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
        return {
            "total_subdomains": len(self.subdomains),
            "alive_subdomains": sum(1 for s in self.subdomains if s.alive),
            "unique_urls": len(set(
                h.url for h in self.httpx_results if h.url
            )),
            "total_ports": len(self.port_results),
            "unique_open_ports": len(set(
                p for pr in self.port_results for p in pr.open_ports.split(",")
            )) if self.port_results else 0,
            "nuclei_findings": len(self.nuclei_findings),
            "nuclei_by_severity": self._count_by_severity(),
            "katana_urls": len(self.katana_urls),
            "unique_katana_urls": len(set(k.url for k in self.katana_urls)),
            "js_files": len(self.js_files),
            "active_js_files": sum(1 for j in self.js_files if j.is_active),
            "js_findings": len(self.js_findings),
            "js_findings_by_category": self._count_js_categories(),
            "critical_js_findings": self._count_critical_js(),
            "asn_ranges": len(self.asn_ranges),
            "asn_ips": len(self.asn_ips),
            "alive_asn_ips": sum(1 for a in self.asn_ips if a.alive),
            "total_runs": len(self.run_history),
            "last_run": self.run_history[0].started_at if self.run_history else None,
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

        # Get program info
        prog_row = self.conn.execute(
            "SELECT * FROM programs WHERE id = ?", (program_id,)
        ).fetchone()
        if not prog_row:
            raise ValueError(f"Program ID {program_id} not found")

        # Get scope domains
        scope_rows = self.conn.execute(
            "SELECT root_domain FROM scope_domains WHERE program_id = ? ORDER BY root_domain",
            (program_id,)
        ).fetchall()
        scope_domains = [r["root_domain"] for r in scope_rows]

        # Calculate stats
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

        # Extract subdomains with port and nuclei count
        data.subdomains = self._extract_subdomains(program_id)

        # Extract HTTPX results
        data.httpx_results = self._extract_httpx_results(program_id)

        # Extract port results
        data.port_results = self._extract_port_results(program_id)

        # Extract nuclei findings (with optional severity filter)
        data.nuclei_findings = self._extract_nuclei_findings(program_id, severity_filter)

        # Extract katana URLs
        data.katana_urls = self._extract_katana_urls(program_id)

        # Extract JS files and findings
        data.js_files = self._extract_js_files(program_id)
        data.js_findings = self._extract_js_findings(program_id)

        # Extract ASN data
        data.asn_ranges = self._extract_asn_ranges(program_id)
        data.asn_ips = self._extract_asn_ips(program_id)

        # Extract run history
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
# HTML Report Generator
# =============================================================================

class HTMLReportGenerator:
    CRITICAL_JS_CATEGORIES = {"api_key", "aws_key", "aws_secret", "google_api_key", "credential", "jwt"}
    SEVERITY_COLORS = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
        "info": "#6b7280",
        "unknown": "#6b7280",
    }
    SEVERITY_BG = {
        "critical": "rgba(220,38,38,0.15)",
        "high": "rgba(234,88,12,0.15)",
        "medium": "rgba(202,138,4,0.15)",
        "low": "rgba(37,99,235,0.15)",
        "info": "rgba(107,114,128,0.15)",
        "unknown": "rgba(107,114,128,0.15)",
    }

    def __init__(self, data: ExportData):
        self.data = data
        self.summary = data.get_summary()

    def generate(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        html_content = self._build_html()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] HTML report exported: {output_path}")

    def _build_html(self) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Report - {escape(self.data.program.name)}</title>
    <style>{self._get_css()}</style>
</head>
<body>
    <div class="container">
        {self._render_header()}
        {self._render_summary_cards()}
        {self._render_tabs()}
        {self._render_tab_content()}
    </div>
    <script>{self._get_js()}</script>
</body>
</html>"""

    def _render_header(self) -> str:
        return f"""
        <header class="header">
            <div class="header-content">
                <h1>🛡️ Recon Report</h1>
                <div class="program-info">
                    <span class="program-name">{escape(self.data.program.name)}</span>
                    <span class="export-time">Exported: {escape(self.data.exported_at)}</span>
                </div>
                <div class="scope-tags">
                    {"".join(f'<span class="scope-tag">{escape(d)}</span>' for d in self.data.program.scope_domains[:10])}
                    {f'<span class="scope-tag more">+{len(self.data.program.scope_domains) - 10} more</span>' if len(self.data.program.scope_domains) > 10 else ''}
                </div>
            </div>
        </header>"""

    def _render_summary_cards(self) -> str:
        s = self.summary
        cards = [
            ("🌐", "Subdomains", s["total_subdomains"], f"{s['alive_subdomains']} alive"),
            ("🔗", "Unique URLs", s["unique_urls"], f"{len(self.data.httpx_results)} total probes"),
            ("🚪", "Open Ports", s["unique_open_ports"], f"{s['total_ports']} hosts scanned"),
            ("⚡", "Vulnerabilities", s["nuclei_findings"], self._severity_badges(s["nuclei_by_severity"])),
            ("🕷️", "Katana URLs", s["unique_katana_urls"], f"{s['katana_urls']} total found"),
            ("📜", "JS Files", s["active_js_files"], f"{s['js_files']} total"),
            ("🔍", "JS Findings", s["js_findings"], f"{s['critical_js_findings']} critical"),
            ("📡", "ASN IPs", s["alive_asn_ips"], f"{s['asn_ranges']} ranges"),
        ]
        return f"""
        <div class="summary-grid">
            {"".join(f'''
            <div class="summary-card">
                <div class="card-icon">{icon}</div>
                <div class="card-value">{value:,}</div>
                <div class="card-label">{label}</div>
                <div class="card-sub">{sub}</div>
            </div>''' for icon, label, value, sub in cards)}
        </div>"""

    def _severity_badges(self, counts: dict[str, int]) -> str:
        badges = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            if counts.get(sev, 0) > 0:
                badges.append(
                    f'<span class="sev-badge sev-{sev}">{counts[sev]}</span>'
                )
        return " ".join(badges)

    def _render_tabs(self) -> str:
        tabs = [
            ("subdomains", "🌐 Subdomains", len(self.data.subdomains)),
            ("urls", "🔗 URLs", len(self.data.httpx_results)),
            ("ports", "🚪 Ports", len(self.data.port_results)),
            ("vulns", "⚡ Vulnerabilities", len(self.data.nuclei_findings)),
            ("katana", "🕷️ Katana", len(self.data.katana_urls)),
            ("jsfiles", "📜 JS Files", len(self.data.js_files)),
            ("jsfindings", "🔍 JS Findings", len(self.data.js_findings)),
            ("asn", "📡 ASN", len(self.data.asn_ips)),
            ("history", "📊 History", len(self.data.run_history)),
        ]
        return f"""
        <div class="tabs-container">
            <div class="tabs">
                {"".join(f'<button class="tab" data-tab="{tid}" onclick="switchTab(\'{tid}\')">{label} <span class="tab-count">{count:,}</span></button>' for tid, label, count in tabs)}
            </div>
            <div class="tab-actions">
                <input type="text" class="search-input" placeholder="Filter..." oninput="filterTable(this.value)">
                <button class="btn btn-secondary" onclick="downloadCurrentTab()">📥 Download CSV</button>
                <button class="btn btn-primary" onclick="downloadJSON()">📄 Download JSON</button>
            </div>
        </div>"""

    def _render_tab_content(self) -> str:
        return f"""
        <div class="tab-content">
            <div id="tab-subdomains" class="tab-pane active">{self._render_subdomains_table()}</div>
            <div id="tab-urls" class="tab-pane">{self._render_urls_table()}</div>
            <div id="tab-ports" class="tab-pane">{self._render_ports_table()}</div>
            <div id="tab-vulns" class="tab-pane">{self._render_vulns_table()}</div>
            <div id="tab-katana" class="tab-pane">{self._render_katana_table()}</div>
            <div id="tab-jsfiles" class="tab-pane">{self._render_jsfiles_table()}</div>
            <div id="tab-jsfindings" class="tab-pane">{self._render_jsfindings_table()}</div>
            <div id="tab-asn" class="tab-pane">{self._render_asn_table()}</div>
            <div id="tab-history" class="tab-pane">{self._render_history_table()}</div>
        </div>"""

    def _render_subdomains_table(self) -> str:
        rows = []
        for s in self.data.subdomains:
            status_class = "alive" if s.alive else "dead"
            status_text = f"{s.http_status or '—'}" if s.alive else "DEAD"
            ports_str = ", ".join(s.ports[:5]) + (f" +{len(s.ports)-5}" if len(s.ports) > 5 else "")
            tech_str = (s.http_tech or "")[:60]
            rows.append(f"""
            <tr>
                <td><input type="checkbox" class="row-select" value="{escape(s.host)}"></td>
                <td class="mono">{escape(s.host)}</td>
                <td><span class="status-badge {status_class}">{status_text}</span></td>
                <td class="truncate" title="{escape(s.http_title or '')}">{escape(s.http_title or '—')}</td>
                <td class="truncate" title="{escape(tech_str)}">{escape(tech_str) or '—'}</td>
                <td class="mono">{escape(ports_str) or '—'}</td>
                <td>{f'<span class="vuln-count">{s.nuclei_count}</span>' if s.nuclei_count > 0 else '—'}</td>
                <td class="date">{escape(s.last_seen[:10])}</td>
                <td>{f'<a href="{escape(s.http_url)}" target="_blank" class="link">↗</a>' if s.http_url else '—'}</td>
            </tr>""")
        return self._table_wrapper(
            ["", "Host", "Status", "Title", "Technology", "Ports", "Vulns", "Last Seen", ""],
            rows,
            "subdomains"
        )

    def _render_urls_table(self) -> str:
        rows = []
        for h in self.data.httpx_results:
            tech = (h.tech or "")[:50]
            rows.append(f"""
            <tr>
                <td><input type="checkbox" class="row-select" value="{escape(h.url or '')}"></td>
                <td class="mono truncate">{escape(h.url or '—')}</td>
                <td><span class="status-badge {'alive' if h.status_code and h.status_code < 400 else 'dead'}">{h.status_code or '—'}</span></td>
                <td class="truncate">{escape(h.method or '—')}</td>
                <td class="truncate">{escape(h.title or '—')}</td>
                <td class="truncate" title="{escape(tech)}">{escape(tech) or '—'}</td>
                <td class="mono">{escape(h.webserver or '—')}</td>
                <td class="mono">{escape(h.host_ip or '—')}</td>
                <td>{f'<span class="cdn-badge">{escape(h.cdn_name)}</span>' if h.cdn_name else '—'}</td>
                <td class="date">{escape(h.scanned_at[:10])}</td>
            </tr>""")
        return self._table_wrapper(
            ["", "URL", "Status", "Method", "Title", "Tech", "Server", "IP", "CDN", "Scanned"],
            rows,
            "urls"
        )

    def _render_ports_table(self) -> str:
        rows = []
        for p in self.data.port_results:
            ports = p.open_ports.split(",")
            port_badges = " ".join(f'<span class="port-badge">{escape(port.strip())}</span>' for port in ports[:10])
            if len(ports) > 10:
                port_badges += f'<span class="port-badge more">+{len(ports)-10}</span>'
            rows.append(f"""
            <tr>
                <td><input type="checkbox" class="row-select" value="{escape(p.subdomain)}"></td>
                <td class="mono">{escape(p.subdomain)}</td>
                <td class="mono">{escape(p.host or p.subdomain)}</td>
                <td class="mono">{escape(p.ip or '—')}</td>
                <td><div class="port-list">{port_badges}</div></td>
                <td class="date">{escape(p.scanned_at[:10])}</td>
            </tr>""")
        return self._table_wrapper(
            ["", "Subdomain", "Host", "IP", "Open Ports", "Scanned"],
            rows,
            "ports"
        )

    def _render_vulns_table(self) -> str:
        rows = []
        for n in self.data.nuclei_findings:
            sev = (n.severity or "unknown").lower()
            rows.append(f"""
            <tr class="vuln-row sev-{sev}">
                <td><input type="checkbox" class="row-select" value="{escape(n.url or n.subdomain)}"></td>
                <td><span class="sev-badge sev-{sev}">{escape(n.severity or 'unknown').upper()}</span></td>
                <td class="mono truncate">{escape(n.subdomain)}</td>
                <td class="mono truncate">{escape(n.url or '—')}</td>
                <td class="truncate">{escape(n.name or '—')}</td>
                <td class="mono truncate">{escape(n.template_id or '—')}</td>
                <td class="date">{escape(n.scanned_at[:10])}</td>
            </tr>""")
        return self._table_wrapper(
            ["", "Severity", "Host", "URL", "Name", "Template", "Found"],
            rows,
            "vulns"
        )

    def _render_katana_table(self) -> str:
        rows = []
        for k in self.data.katana_urls:
            rows.append(f"""
            <tr>
                <td><input type="checkbox" class="row-select" value="{escape(k.url)}"></td>
                <td class="mono truncate">{escape(k.url)}</td>
                <td class="mono">{escape(k.subdomain)}</td>
                <td class="date">{escape(k.scanned_at[:10])}</td>
            </tr>""")
        return self._table_wrapper(
            ["", "URL", "Source", "Found"],
            rows,
            "katana"
        )

    def _render_jsfiles_table(self) -> str:
        rows = []
        for j in self.data.js_files:
            active_class = "active" if j.is_active else "inactive"
            rows.append(f"""
            <tr class="{active_class}">
                <td><input type="checkbox" class="row-select" value="{escape(j.url)}"></td>
                <td class="mono truncate">{escape(j.url)}</td>
                <td class="mono truncate">{escape(j.source_url or '—')}</td>
                <td>{j.content_length or '—'}</td>
                <td class="mono hash">{escape((j.current_hash or '')[:12])}…</td>
                <td><span class="status-badge {active_class}">{'Active' if j.is_active else 'Inactive'}</span></td>
                <td class="date">{escape(j.last_seen_at[:10])}</td>
                <td class="date">{escape((j.last_changed_at or j.first_seen_at)[:10])}</td>
            </tr>""")
        return self._table_wrapper(
            ["", "URL", "Source", "Size", "Hash", "Status", "Last Seen", "Changed"],
            rows,
            "jsfiles"
        )

    def _render_jsfindings_table(self) -> str:
        rows = []
        for jf in self.data.js_findings:
            is_critical = jf.category in self.CRITICAL_JS_CATEGORIES
            crit_class = "critical-finding" if is_critical else ""
            value_display = jf.value[:100] + ("…" if len(jf.value) > 100 else "")
            rows.append(f"""
            <tr class="{crit_class} {'inactive' if not jf.is_active else ''}">
                <td><input type="checkbox" class="row-select" value="{escape(jf.value)}"></td>
                <td><span class="category-badge {'critical-cat' if is_critical else ''}">{escape(jf.category)}</span></td>
                <td class="mono truncate" title="{escape(jf.value)}">{escape(value_display)}</td>
                <td class="truncate">{escape(jf.source_type)}</td>
                <td class="mono truncate">{escape(jf.source_url or '—')}</td>
                <td class="truncate context" title="{escape(jf.context or '')}">{escape((jf.context or '')[:60]) or '—'}</td>
                <td><span class="status-badge {'active' if jf.is_active else 'inactive'}">{'Active' if jf.is_active else 'Old'}</span></td>
                <td class="date">{escape(jf.last_seen_at[:10])}</td>
            </tr>""")
        return self._table_wrapper(
            ["", "Category", "Value", "Source Type", "Source URL", "Context", "Status", "Last Seen"],
            rows,
            "jsfindings"
        )

    def _render_asn_table(self) -> str:
        # Combine ranges and IPs
        rows = []
        for a in self.data.asn_ips:
            rows.append(f"""
            <tr class="{'alive' if a.alive else 'dead'}">
                <td><input type="checkbox" class="row-select" value="{escape(a.ip)}"></td>
                <td class="mono">{escape(a.ip)}</td>
                <td class="mono">{escape(a.asn or '—')}</td>
                <td class="mono">{escape(a.cidr or '—')}</td>
                <td><span class="status-badge {'alive' if a.alive else 'dead'}">{'Alive' if a.alive else 'Dead'}</span></td>
                <td class="date">{escape(a.last_seen[:10])}</td>
            </tr>""")
        return self._table_wrapper(
            ["", "IP", "ASN", "CIDR", "Status", "Last Seen"],
            rows,
            "asn"
        )

    def _render_history_table(self) -> str:
        rows = []
        for r in self.data.run_history:
            status_class = "success" if r.status == "ok" else "warning" if r.status == "running" else "error"
            rows.append(f"""
            <tr>
                <td class="date">{escape(r.started_at[:19].replace('T', ' '))}</td>
                <td><span class="status-badge {status_class}">{escape(r.status)}</span></td>
                <td>{r.discovered:,}</td>
                <td>{r.new_subdomains:,}</td>
                <td>{r.live_subdomains:,}</td>
                <td><span class="vuln-count">{r.nuclei_findings:,}</span></td>
                <td>{r.katana_urls:,}</td>
                <td>{r.js_files_found:,}</td>
                <td>{r.js_files_changed:,}</td>
                <td>{r.js_findings_new:,}</td>
                <td><span class="critical-count">{r.js_findings_critical:,}</span></td>
                <td class="date">{escape((r.finished_at or '')[:19].replace('T', ' ') if r.finished_at else '—')}</td>
            </tr>""")
        return self._table_wrapper(
            ["Started", "Status", "Discovered", "New Subs", "Live", "Vulns", "Katana", "JS Files", "JS Changed", "JS New", "JS Critical", "Finished"],
            rows,
            "history"
        )

    def _table_wrapper(self, headers: list[str], rows: list[str], table_id: str) -> str:
        header_row = "".join(f"<th>{h}</th>" for h in headers)
        selection_ui = f"""
        <div class="table-toolbar" id="toolbar-{table_id}">
            <label class="select-all-label">
                <input type="checkbox" onchange="toggleSelectAll('{table_id}', this.checked)">
                Select All
            </label>
            <button class="btn btn-small" onclick="downloadSelected('{table_id}')">📥 Download Selected</button>
            <button class="btn btn-small" onclick="copySelected('{table_id}')">📋 Copy Selected</button>
            <span class="row-count" id="count-{table_id}">{len(rows):,} rows</span>
        </div>"""
        return f"""
        {selection_ui}
        <div class="table-container">
            <table id="table-{table_id}">
                <thead><tr>{header_row}</tr></thead>
                <tbody>{"".join(rows)}</tbody>
            </table>
        </div>"""

    def _get_css(self) -> str:
        return """
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent: #3b82f6;
            --accent-hover: #2563eb;
            --border: #334155;
            --success: #22c55e;
            --warning: #eab308;
            --error: #ef4444;
            --radius: 8px;
            --shadow: 0 4px 6px -1px rgba(0,0,0,0.3);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-tertiary));
            border-radius: var(--radius);
            padding: 24px;
            margin-bottom: 24px;
            border: 1px solid var(--border);
        }
        .header h1 { font-size: 1.8rem; margin-bottom: 8px; }
        .program-info { display: flex; align-items: center; gap: 16px; margin-bottom: 12px; }
        .program-name { font-size: 1.3rem; font-weight: 600; color: var(--accent); }
        .export-time { color: var(--text-muted); font-size: 0.9rem; }
        .scope-tags { display: flex; flex-wrap: wrap; gap: 8px; }
        .scope-tag {
            background: var(--bg-primary);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            color: var(--text-secondary);
            border: 1px solid var(--border);
        }
        .scope-tag.more { color: var(--text-muted); font-style: italic; }
        
        /* Summary Cards */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .summary-card {
            background: var(--bg-secondary);
            border-radius: var(--radius);
            padding: 20px;
            border: 1px solid var(--border);
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }
        .card-icon { font-size: 1.5rem; margin-bottom: 8px; }
        .card-value { font-size: 2rem; font-weight: 700; color: var(--text-primary); }
        .card-label { font-size: 0.9rem; color: var(--text-secondary); margin-top: 4px; }
        .card-sub { font-size: 0.8rem; color: var(--text-muted); margin-top: 8px; }
        
        /* Severity Badges */
        .sev-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .sev-critical { background: rgba(220,38,38,0.2); color: #fca5a5; border: 1px solid #dc2626; }
        .sev-high { background: rgba(234,88,12,0.2); color: #fdba74; border: 1px solid #ea580c; }
        .sev-medium { background: rgba(202,138,4,0.2); color: #fde047; border: 1px solid #ca8a04; }
        .sev-low { background: rgba(37,99,235,0.2); color: #93c5fd; border: 1px solid #2563eb; }
        .sev-info, .sev-unknown { background: rgba(107,114,128,0.2); color: #d1d5db; border: 1px solid #6b7280; }
        
        /* Tabs */
        .tabs-container {
            background: var(--bg-secondary);
            border-radius: var(--radius);
            border: 1px solid var(--border);
            margin-bottom: 24px;
            overflow: hidden;
        }
        .tabs {
            display: flex;
            overflow-x: auto;
            border-bottom: 1px solid var(--border);
            scrollbar-width: thin;
        }
        .tabs::-webkit-scrollbar { height: 4px; }
        .tabs::-webkit-scrollbar-track { background: var(--bg-secondary); }
        .tabs::-webkit-scrollbar-thumb { background: var(--bg-tertiary); border-radius: 2px; }
        .tab {
            background: none;
            border: none;
            color: var(--text-secondary);
            padding: 14px 20px;
            cursor: pointer;
            font-size: 0.9rem;
            white-space: nowrap;
            border-bottom: 2px solid transparent;
            transition: all 0.2s;
        }
        .tab:hover { color: var(--text-primary); background: var(--bg-tertiary); }
        .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
        .tab-count {
            background: var(--bg-tertiary);
            padding: 1px 8px;
            border-radius: 10px;
            font-size: 0.75rem;
            margin-left: 6px;
        }
        .tab.active .tab-count { background: rgba(59,130,246,0.3); }
        .tab-actions {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            border-top: 1px solid var(--border);
        }
        .search-input {
            flex: 1;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 8px 12px;
            color: var(--text-primary);
            font-size: 0.9rem;
        }
        .search-input:focus { outline: none; border-color: var(--accent); }
        
        /* Buttons */
        .btn {
            padding: 8px 16px;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.2s;
            white-space: nowrap;
        }
        .btn-primary { background: var(--accent); color: white; }
        .btn-primary:hover { background: var(--accent-hover); }
        .btn-secondary { background: var(--bg-tertiary); color: var(--text-primary); }
        .btn-secondary:hover { background: var(--border); }
        .btn-small { padding: 4px 12px; font-size: 0.8rem; }
        
        /* Tab Content */
        .tab-pane { display: none; }
        .tab-pane.active { display: block; }
        
        /* Table Toolbar */
        .table-toolbar {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 12px 16px;
            background: var(--bg-secondary);
            border-radius: var(--radius) var(--radius) 0 0;
            border: 1px solid var(--border);
            border-bottom: none;
        }
        .select-all-label {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.85rem;
            color: var(--text-secondary);
            cursor: pointer;
        }
        .row-count { margin-left: auto; color: var(--text-muted); font-size: 0.85rem; }
        
        /* Tables */
        .table-container {
            overflow-x: auto;
            border: 1px solid var(--border);
            border-radius: 0 0 var(--radius) var(--radius);
            max-height: 70vh;
            overflow-y: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        tr:hover { background: rgba(59,130,246,0.05); }
        .mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; }
        .truncate { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .date { white-space: nowrap; color: var(--text-muted); }
        .hash { color: var(--text-muted); }
        
        /* Status Badges */
        .status-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        .status-badge.alive, .status-badge.active, .status-badge.success {
            background: rgba(34,197,94,0.15);
            color: #86efac;
            border: 1px solid #22c55e;
        }
        .status-badge.dead, .status-badge.inactive, .status-badge.error {
            background: rgba(239,68,68,0.15);
            color: #fca5a5;
            border: 1px solid #ef4444;
        }
        .status-badge.warning {
            background: rgba(234,179,8,0.15);
            color: #fde047;
            border: 1px solid #eab308;
        }
        
        /* Special Elements */
        .vuln-count {
            background: rgba(220,38,38,0.2);
            color: #fca5a5;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 600;
        }
        .critical-count {
            background: rgba(220,38,38,0.3);
            color: #fca5a5;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 700;
        }
        .port-badge {
            display: inline-block;
            background: var(--bg-tertiary);
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.75rem;
            margin: 2px;
            font-family: monospace;
        }
        .port-badge.more { color: var(--text-muted); font-style: italic; }
        .port-list { display: flex; flex-wrap: wrap; gap: 2px; }
        .cdn-badge {
            background: rgba(139,92,246,0.2);
            color: #c4b5fd;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
        }
        .category-badge {
            display: inline-block;
            background: var(--bg-tertiary);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 500;
        }
        .category-badge.critical-cat {
            background: rgba(220,38,38,0.2);
            color: #fca5a5;
            border: 1px solid #dc2626;
        }
        .link {
            color: var(--accent);
            text-decoration: none;
            font-weight: bold;
        }
        .link:hover { text-decoration: underline; }
        .context { font-style: italic; color: var(--text-muted); }
        tr.critical-finding { background: rgba(220,38,38,0.05); }
        tr.inactive { opacity: 0.6; }
        tr.vuln-row.sev-critical { border-left: 3px solid #dc2626; }
        tr.vuln-row.sev-high { border-left: 3px solid #ea580c; }
        
        /* Checkbox Styling */
        input[type="checkbox"] {
            width: 16px;
            height: 16px;
            cursor: pointer;
            accent-color: var(--accent);
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .container { padding: 12px; }
            .header h1 { font-size: 1.4rem; }
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            .tab-actions { flex-wrap: wrap; }
            .search-input { width: 100%; order: -1; }
            .table-toolbar { flex-wrap: wrap; }
        }
        
        /* Hidden rows for filtering */
        tr.hidden { display: none; }
        """

    def _get_js(self) -> str:
        return f"""
        const reportData = {json.dumps(self.data.to_dict(), default=str, ensure_ascii=False)};
        
        let currentTab = 'subdomains';
        
        function switchTab(tabId) {{
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            document.querySelector(`[data-tab="${{tabId}}"]`).classList.add('active');
            document.getElementById(`tab-${{tabId}}`).classList.add('active');
            currentTab = tabId;
        }}
        
        function filterTable(query) {{
            query = query.toLowerCase().trim();
            const table = document.getElementById(`table-${{currentTab}}`);
            if (!table) return;
            
            const rows = table.querySelectorAll('tbody tr');
            let visible = 0;
            
            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                const isHidden = query && !text.includes(query);
                row.classList.toggle('hidden', isHidden);
                if (!isHidden) visible++;
            }});
            
            const countEl = document.getElementById(`count-${{currentTab}}`);
            if (countEl) {{
                countEl.textContent = `${{visible.toLocaleString()}} rows` + (query ? ` (filtered from ${{rows.length.toLocaleString()}})` : '');
            }}
        }}
        
        function toggleSelectAll(tableId, checked) {{
            const table = document.getElementById(`table-${{tableId}}`);
            if (!table) return;
            table.querySelectorAll('.row-select:not(:disabled)').forEach(cb => {{
                if (!cb.closest('tr').classList.contains('hidden')) {{
                    cb.checked = checked;
                }}
            }});
        }}
        
        function getSelectedValues(tableId) {{
            const table = document.getElementById(`table-${{tableId}}`);
            if (!table) return [];
            return Array.from(table.querySelectorAll('.row-select:checked'))
                .map(cb => cb.value)
                .filter(v => v);
        }}
        
        function downloadSelected(tableId) {{
            const values = getSelectedValues(tableId);
            if (values.length === 0) {{
                alert('No rows selected. Click checkboxes to select rows.');
                return;
            }}
            downloadText(values.join('\\n'), `recon_${{tableId}}_selected.txt`, 'text/plain');
        }}
        
        function copySelected(tableId) {{
            const values = getSelectedValues(tableId);
            if (values.length === 0) {{
                alert('No rows selected.');
                return;
            }}
            navigator.clipboard.writeText(values.join('\\n')).then(() => {{
                alert(`Copied ${{values.length}} items to clipboard!`);
            }});
        }}
        
        function downloadCurrentTab() {{
            const table = document.getElementById(`table-${{currentTab}}`);
            if (!table) return;
            
            const headers = Array.from(table.querySelectorAll('thead th'))
                .map(th => th.textContent.trim())
                .filter(h => h);
            
            const rows = Array.from(table.querySelectorAll('tbody tr:not(.hidden)'))
                .map(row => Array.from(row.querySelectorAll('td'))
                    .map(td => td.textContent.trim().replace(/\\n/g, ' '))
                    .join(',')
                );
            
            const csv = [headers.join(','), ...rows].join('\\n');
            downloadText(csv, `recon_${{currentTab}}.csv`, 'text/csv');
        }}
        
        function downloadJSON() {{
            const json = JSON.stringify(reportData, null, 2);
            downloadText(json, `recon_${{reportData.program.name}}.json`, 'application/json');
        }}
        
        function downloadText(content, filename, type) {{
            const blob = new Blob([content], {{ type }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            URL.revokeObjectURL(url);
        }}
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {{
            if (e.ctrlKey || e.metaKey) {{
                if (e.key === 'f') {{
                    e.preventDefault();
                    document.querySelector('.search-input').focus();
                }}
                if (e.key === 's') {{
                    e.preventDefault();
                    downloadJSON();
                }}
            }}
        }});
        
        // Auto-switch to vulnerabilities tab if critical findings exist
        (function() {{
            const criticalCount = {self.summary['nuclei_by_severity'].get('critical', 0)} +
                                 {self.summary['nuclei_by_severity'].get('high', 0)} +
                                 {self.summary['critical_js_findings']};
            if (criticalCount > 0) {{
                console.log(`%c⚠️ ${{criticalCount}} critical/high findings detected!`, 'color: #fca5a5; font-size: 14px;');
            }}
        }})();
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
                print(f"    - Skipping disabled program: {prog['name']}")
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
                print(f"[!] Error exporting {prog['name']}: {e}")

        # Generate index page
        _generate_index(output_dir, programs, extractor, severity_filter)

    finally:
        extractor.close()


def _generate_index(
    output_dir: Path,
    programs: list[dict],
    extractor: DatabaseExtractor,
    severity_filter: Optional[list[str]]
) -> None:
    program_cards = []
    for prog in programs:
        if not prog["enabled"]:
            continue
        stats = extractor._get_program_stats(prog["id"])
        program_cards.append(f"""
        <div class="program-card">
            <h3>{escape(prog['name'])}</h3>
            <div class="program-stats">
                <div class="stat"><span class="stat-value">{stats.get('subdomains', 0):,}</span><span class="stat-label">Subdomains</span></div>
                <div class="stat"><span class="stat-value">{stats.get('nuclei_findings', 0):,}</span><span class="stat-label">Vulns</span></div>
                <div class="stat"><span class="stat-value">{stats.get('katana_results', 0):,}</span><span class="stat-label">Katana</span></div>
                <div class="stat"><span class="stat-value">{stats.get('js_findings', 0):,}</span><span class="stat-label">JS Findings</span></div>
            </div>
            <div class="program-links">
                <a href="{escape(prog['name'])}/{escape(prog['name'])}_report.html" class="btn btn-primary">View Report</a>
                <a href="{escape(prog['name'])}/{escape(prog['name'])}_report.json" class="btn btn-secondary">JSON</a>
            </div>
            <div class="program-meta">
                Last scanned: {escape((prog['last_scanned_at'] or 'Never')[:10])}
            </div>
        </div>""")

    index_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recon Reports Index</title>
    <style>
        :root {{ --bg: #0f172a; --bg2: #1e293b; --bg3: #334155; --text: #f1f5f9; --text2: #94a3b8; --accent: #3b82f6; --border: #334155; }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
        h1 {{ text-align: center; margin-bottom: 40px; font-size: 2rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 24px; }}
        .program-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; padding: 24px; transition: transform 0.2s; }}
        .program-card:hover {{ transform: translateY(-4px); }}
        .program-card h3 {{ color: var(--accent); margin-bottom: 16px; font-size: 1.3rem; }}
        .program-stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }}
        .stat {{ text-align: center; }}
        .stat-value {{ display: block; font-size: 1.5rem; font-weight: 700; }}
        .stat-label {{ font-size: 0.8rem; color: var(--text2); }}
        .program-links {{ display: flex; gap: 12px; margin-bottom: 16px; }}
        .btn {{ padding: 8px 16px; border-radius: 6px; text-decoration: none; font-size: 0.9rem; font-weight: 500; }}
        .btn-primary {{ background: var(--accent); color: white; }}
        .btn-secondary {{ background: var(--bg3); color: var(--text); }}
        .program-meta {{ font-size: 0.8rem; color: var(--text2); }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Recon Reports</h1>
        <div class="grid">{"".join(program_cards)}</div>
    </div>
</body>
</html>"""

    index_path = output_dir / "index.html"
    index_path.write_text(index_html, encoding="utf-8")
    print(f"\n[+] Index page created: {index_path}")


# =============================================================================
# CLI Interface
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export bug bounty recon data to HTML reports and JSON",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all programs in database
  python export.py --db ./recon.db --list-programs

  # Export single program (both HTML and JSON)
  python export.py --db ./recon.db --program "company_1"

  # Export all programs to ./reports directory
  python export.py --db ./recon.db --all-programs --output ./reports

  # Export only critical and high severity findings
  python export.py --db ./recon.db --program "company_1" --severities critical,high

  # Export only JSON format
  python export.py --db ./recon.db --program "company_1" --format json

  # Export to custom output path
  python export.py --db ./recon.db --program "company_1" --output /tmp/company1_export
"""
    )

    parser.add_argument(
        "--db", "-d",
        type=Path,
        required=True,
        help="Path to recon.db SQLite database"
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--program", "-p",
        type=str,
        help="Export a specific program by name"
    )
    mode.add_argument(
        "--all-programs", "-a",
        action="store_true",
        help="Export all enabled programs"
    )
    mode.add_argument(
        "--list-programs", "-l",
        action="store_true",
        help="List all programs in the database and exit"
    )

    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output directory (default: ./exports/<program_name>)"
    )

    parser.add_argument(
        "--format", "-f",
        type=str,
        choices=["html", "json", "both"],
        default="both",
        help="Output format (default: both)"
    )

    parser.add_argument(
        "--severities", "-s",
        type=str,
        default=None,
        help="Comma-separated severity filter for nuclei findings (e.g., critical,high)"
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress non-error output"
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # Validate database exists
    if not args.db.exists():
        print(f"[!] Database not found: {args.db}", file=sys.stderr)
        return 1

    extractor = DatabaseExtractor(args.db)
    try:
        extractor.connect()

        # List programs mode
        if args.list_programs:
            programs = extractor.list_programs()
            if not programs:
                print("[!] No programs found in database")
                return 1

            print(f"\n{'ID':<5} {'Enabled':<10} {'Last Scanned':<20} {'Program Name'}")
            print("-" * 70)
            for p in programs:
                enabled = "✓" if p["enabled"] else "✗"
                last = (p["last_scanned_at"] or "Never")[:19].replace("T", " ")
                print(f"{p['id']:<5} {enabled:<10} {last:<20} {p['name']}")
            print(f"\nTotal: {len(programs)} programs")
            return 0

        # Parse severity filter
        severity_filter = None
        if args.severities:
            severity_filter = [s.strip().lower() for s in args.severities.split(",")]
            valid_sevs = {"critical", "high", "medium", "low", "info"}
            invalid = set(severity_filter) - valid_sevs
            if invalid:
                print(f"[!] Invalid severities: {invalid}. Valid: {valid_sevs}", file=sys.stderr)
                return 1

        # Export all programs
        if args.all_programs:
            output_dir = args.output or args.db.parent / "exports"
            if not args.quiet:
                print(f"[*] Exporting all programs to: {output_dir}")
            export_all_programs(args.db, output_dir, severity_filter, args.format)
            return 0

        # Export single program
        if args.program:
            program_id = extractor.get_program_id(args.program)
            if not program_id:
                print(f"[!] Program not found: {args.program}", file=sys.stderr)
                print("[!] Use --list-programs to see available programs", file=sys.stderr)
                return 1

            output_dir = args.output or args.db.parent / "exports" / args.program

            if not args.quiet:
                print(f"[*] Exporting program: {args.program} (ID: {program_id})")
                if severity_filter:
                    print(f"[*] Severity filter: {', '.join(severity_filter)}")

            data = extractor.extract_program(program_id, severity_filter)

            if args.format in ("json", "both"):
                export_json(data, output_dir / f"{args.program}_report.json")

            if args.format in ("html", "both"):
                generator = HTMLReportGenerator(data)
                generator.generate(output_dir / f"{args.program}_report.html")

            if not args.quiet:
                print(f"\n[*] Export complete!")
                print(f"    Output directory: {output_dir}")

            return 0

    except FileNotFoundError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[!] Unexpected error: {e}", file=sys.stderr)
        if args.quiet:
            raise
        return 1
    finally:
        extractor.close()


if __name__ == "__main__":
    sys.exit(main())