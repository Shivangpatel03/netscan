"""
reporter.py — Scan Results Display & Report Export

Handles:
  - Rich terminal output (color-coded tables, panels, stat cards)
  - Plain-text .txt report export
  - Remediation recommendation generation
"""

from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich.align import Align
from rich import box
from vuln_db import RISK_STYLE

console = Console()


# ── Remediation logic ─────────────────────────────────────────────────────────

def build_recommendations(open_ports: list[dict]) -> list[str]:
    """Generate context-aware remediation recommendations based on findings."""
    port_set = {p["port"] for p in open_ports}
    recos: list[str] = []

    critical = [p for p in open_ports if p["risk"] == "CRITICAL"]
    if critical:
        names = ", ".join(f"{p['service']} ({p['port']})" for p in critical[:3])
        recos.append(
            f"URGENT: {len(critical)} CRITICAL service(s) found ({names}) — "
            "isolate or patch immediately before any other action."
        )

    if 23 in port_set:
        recos.append("Disable Telnet (23) — credentials sent in cleartext. Replace with SSH.")
    if 445 in port_set:
        recos.append("Disable SMBv1 (445) — apply MS17-010 patch to prevent EternalBlue (CVE-2017-0144).")
    if 3389 in port_set:
        recos.append("Restrict RDP (3389) behind VPN — BlueKeep (CVE-2019-0708) is actively exploited in the wild.")
    if 6379 in port_set:
        recos.append("Add 'requirepass' to Redis config (6379) — unauthenticated Redis allows arbitrary Lua RCE.")
    if 27017 in port_set:
        recos.append("Enable MongoDB authentication (27017) — no-auth instance exposes the entire database.")
    if 21 in port_set:
        recos.append("Replace FTP (21) with SFTP over SSH — FTP transmits credentials and data in cleartext.")
    if 9200 in port_set:
        recos.append("Bind Elasticsearch (9200) to 127.0.0.1 — public access exposes all indexed data without auth.")
    if 2375 in port_set:
        recos.append("Disable Docker API on TCP (2375) immediately — unauthenticated access = full host takeover.")
    if 4444 in port_set:
        recos.append("CRITICAL: Port 4444 open — investigate for active Metasploit handler or malware backdoor.")
    if 8888 in port_set:
        recos.append("Secure Jupyter Notebook (8888) — add token auth and bind to localhost only.")
    if 10000 in port_set:
        recos.append("Patch Webmin (10000) — CVE-2019-15107 allows unauthenticated RCE via password reset.")
    if 512 in port_set or 513 in port_set or 514 in port_set:
        recos.append("Disable r-services (512/513/514) — allow passwordless access, completely insecure.")
    if 6443 in port_set:
        recos.append("Restrict Kubernetes API (6443) — misconfigured cluster API allows full cluster takeover.")
    if 11211 in port_set:
        recos.append("Firewall Memcached UDP/TCP (11211) — used in DDoS amplification attacks (100x factor).")

    # Generic recommendations always added
    recos.append("Apply firewall rules (iptables/ufw/nftables) to restrict all non-essential inbound ports.")
    recos.append("Run authenticated scans periodically and subscribe to CVE advisories for your software versions.")

    return recos[:10]  # Cap at 10


# ── Rich terminal display ─────────────────────────────────────────────────────

def print_banner():
    console.print("""[bold cyan]
 ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝[/bold cyan]
[dim]   Real Network Vulnerability Scanner  v4.0.0  |  Built-in CVE Database[/dim]
""")
    console.print(Rule(style="dim cyan"))


def print_scan_config(target: str, ip: str, hostname: str, profile: str,
                      os_detect: bool, ports_count: int):
    """Print the scan configuration panel before scanning starts."""
    grid = Table.grid(padding=(0, 2))
    grid.add_row("[dim]Target[/dim]",    f"[bold white]{target}[/bold white]")
    grid.add_row("[dim]IP Address[/dim]", f"[bold cyan]{ip}[/bold cyan]")
    grid.add_row("[dim]Hostname[/dim]",   f"[white]{hostname}[/white]")
    grid.add_row("[dim]Profile[/dim]",    f"[bold yellow]{profile.upper()}[/bold yellow]  ({ports_count} ports)")
    grid.add_row("[dim]OS Detect[/dim]",  "[green]Enabled[/green]" if os_detect else "[dim]Disabled[/dim]")
    grid.add_row("[dim]Started[/dim]",    f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")

    console.print(Panel(grid, title="[bold cyan]◈ Scan Configuration[/bold cyan]",
                        border_style="cyan", padding=(1, 2)))
    console.print()


def print_results(open_ports: list[dict], target: str, ip: str, hostname: str,
                  os_name: str, duration: float, profile: str):
    """Print the full results: stats, host info, vulnerability table, recommendations."""

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for p in open_ports:
        counts[p["risk"]] = counts.get(p["risk"], 0) + 1

    # ── Summary stat panels ───────────────────────────────────────────────────
    console.print(Rule("[bold cyan]◈ Scan Summary[/bold cyan]", style="dim cyan"))
    console.print()

    stat_data = [
        (str(len(open_ports)), "OPEN PORTS", "bold cyan"),
        (str(counts["CRITICAL"]),  "CRITICAL",  "bold red"),
        (str(counts["HIGH"]),      "HIGH",      "bold orange3"),
        (str(counts["MEDIUM"]),    "MEDIUM",    "bold yellow"),
        (str(counts["LOW"]),       "LOW",       "bold cyan"),
        (str(counts["INFO"]),      "INFO",      "bold blue"),
    ]
    panels = [
        Panel(Align.center(Text(val, style=style + " bold")),
              title=f"[dim]{lbl}[/dim]", border_style="dim cyan", width=14)
        for val, lbl, style in stat_data
    ]
    console.print(Columns(panels, equal=True, expand=False))
    console.print()

    # ── Host info ─────────────────────────────────────────────────────────────
    host_grid = Table.grid(padding=(0, 3))
    host_grid.add_row("[dim]Target[/dim]",   f"[white]{target}[/white]",
                      "[dim]IP[/dim]",       f"[cyan]{ip}[/cyan]")
    host_grid.add_row("[dim]Hostname[/dim]", f"[white]{hostname}[/white]",
                      "[dim]OS[/dim]",       f"[green]{os_name or 'Unknown'}[/green]")
    host_grid.add_row("[dim]Duration[/dim]", f"[yellow]{duration:.2f}s[/yellow]",
                      "[dim]Profile[/dim]",  f"[yellow]{profile.upper()}[/yellow]")

    console.print(Panel(host_grid, title="[bold cyan]◈ Host Information[/bold cyan]",
                        border_style="dim cyan", padding=(1, 2)))
    console.print()

    # ── Vulnerability table ───────────────────────────────────────────────────
    if not open_ports:
        console.print(Panel(
            "[green]  ✔  No open ports detected on this target.[/green]\n"
            "[dim]  All scanned ports are closed or filtered.[/dim]",
            border_style="green", padding=(1, 2)
        ))
    else:
        tbl = Table(
            title="[bold cyan]◈ Open Ports & Vulnerabilities[/bold cyan]",
            box=box.ROUNDED,
            border_style="dim cyan",
            header_style="bold dim cyan",
            show_lines=True,
            padding=(0, 1),
        )
        tbl.add_column("PORT",        style="bold cyan",   width=7,  justify="right")
        tbl.add_column("SERVICE",     style="bold white",  width=16)
        tbl.add_column("BANNER",      style="dim white",   width=28)
        tbl.add_column("RISK",        width=12,            justify="center")
        tbl.add_column("CVE",         style="yellow",      width=18)
        tbl.add_column("DESCRIPTION", style="dim white",   min_width=30)

        for p in open_ports:
            style, icon = RISK_STYLE.get(p["risk"], ("white", "⚪"))
            risk_text = Text(f"{icon} {p['risk']}", style=style)
            cve_text  = Text(p["cve"] or "—", style="yellow" if p["cve"] else "dim")
            latency   = f"[dim]{p.get('latency', '?')}ms[/dim]"

            tbl.add_row(
                str(p["port"]),
                p["service"],
                p["banner"][:50] if p["banner"] else "—",
                risk_text,
                cve_text,
                p["desc"],
            )

        console.print(tbl)
    console.print()

    # ── Recommendations ───────────────────────────────────────────────────────
    recos = build_recommendations(open_ports)
    reco_text = Text()
    for i, r in enumerate(recos, 1):
        reco_text.append(f"  {i:02d}. ", style="bold yellow")
        reco_text.append(f"{r}\n", style="white")

    console.print(Panel(reco_text,
                        title="[bold cyan]◈ Remediation Recommendations[/bold cyan]",
                        border_style="dim cyan", padding=(1, 2)))
    console.print()

    # ── Critical alert ────────────────────────────────────────────────────────
    if counts["CRITICAL"] > 0:
        console.print(Panel(
            f"[bold red]  ⚠  {counts['CRITICAL']} CRITICAL vulnerability/vulnerabilities found!\n"
            "[red]  Immediate action required — risk of full system compromise.[/red]",
            border_style="red", padding=(0, 2),
        ))
        console.print()

    console.print(Rule(style="dim"))
    console.print(
        "[dim]  ⚠  FOR AUTHORIZED USE ONLY — "
        "NEVER scan systems without explicit written permission.[/dim]"
    )
    console.print()


# ── Text report export ────────────────────────────────────────────────────────

def save_report(open_ports: list[dict], target: str, ip: str, hostname: str,
                os_name: str, duration: float, profile: str, filename: str):
    """Save a structured plain-text vulnerability report to a file."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for p in open_ports:
        counts[p["risk"]] = counts.get(p["risk"], 0) + 1

    lines = [
        "=" * 72,
        "  NETSCAN v4.0 — Real Network Vulnerability Scanner",
        f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 72,
        "",
        "  TARGET INFORMATION",
        f"  Target    : {target}",
        f"  IP        : {ip}",
        f"  Hostname  : {hostname}",
        f"  OS        : {os_name or 'Unknown'}",
        f"  Profile   : {profile.upper()}",
        f"  Duration  : {duration:.2f}s",
        f"  Open Ports: {len(open_ports)}",
        f"  Critical  : {counts['CRITICAL']}  High: {counts['HIGH']}  "
        f"Medium: {counts['MEDIUM']}  Low: {counts['LOW']}  Info: {counts['INFO']}",
        "",
        "-" * 72,
        f"  {'PORT':<8} {'SERVICE':<18} {'RISK':<10} {'CVE':<18} {'BANNER':<30} DESCRIPTION",
        "-" * 72,
    ]

    for p in open_ports:
        lines.append(
            f"  {p['port']:<8} {p['service']:<18} {p['risk']:<10} "
            f"{(p['cve'] or '—'):<18} {(p['banner'] or '—')[:28]:<30} {p['desc']}"
        )

    lines += [
        "",
        "-" * 72,
        "  REMEDIATION RECOMMENDATIONS",
        "-" * 72,
    ]
    for i, r in enumerate(build_recommendations(open_ports), 1):
        lines.append(f"  {i:02d}. {r}")

    lines += [
        "",
        "=" * 72,
        "  FOR AUTHORIZED USE ONLY — Never scan without explicit written permission.",
        "=" * 72,
    ]

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    console.print(f"\n[bold green]✔  Report saved →[/bold green] [cyan]{filename}[/cyan]\n")
