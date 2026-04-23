#!/usr/bin/env python3
"""
main.py — NetScan v4.0 Entry Point

Usage:
  python main.py                             # Interactive mode
  python main.py -t 192.168.1.1             # Standard scan
  python main.py -t 192.168.1.1 -p quick   # Quick scan (20 ports)
  python main.py -t 192.168.1.1 -p full    # Full scan (1-1024)
  python main.py -t 192.168.1.1 -o out.txt # Save report to file
  python main.py -t 192.168.1.1 --no-os    # Skip OS detection
  python main.py -t 192.168.1.1 --timeout 2.0  # Custom timeout

Requirements:
  pip install rich
"""

import argparse
import sys
import time

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                               TextColumn, TimeElapsedColumn)
except ImportError:
    print("\n[ERROR] 'rich' library not found.")
    print("Install it with:  pip install rich\n")
    sys.exit(1)

from resolver  import resolve_target, validate_target, is_host_up
from scanner   import run_port_scan
from os_detect import detect_os
from reporter  import print_banner, print_scan_config, print_results, save_report
from vuln_db   import PORT_PROFILES

console = Console()


# ── Core scan orchestrator ────────────────────────────────────────────────────

def run_scan(
    target:    str,
    profile:   str  = "standard",
    os_detect: bool = True,
    output:    str  = None,
    timeout:   float = 1.0,
):
    """
    Full scan pipeline:
      1. Validate & resolve target
      2. Check host liveness
      3. Scan ports (real TCP connects)
      4. Detect OS (TTL / SSH banner / HTTP header)
      5. Display results
      6. Optionally save report
    """
    print_banner()

    # ── Step 1: Validate input ────────────────────────────────────────────────
    valid, err = validate_target(target)
    if not valid:
        console.print(f"[bold red]  ✗  Invalid target: {err}[/bold red]\n")
        sys.exit(1)

    # ── Step 2: Resolve hostname / IP ─────────────────────────────────────────
    console.print(f"[dim]  Resolving [bold]{target}[/bold]...[/dim]")
    ip, hostname = resolve_target(target)

    if ip is None:
        console.print(f"\n[bold red]  ✗  Could not resolve '{target}'[/bold red]")
        console.print("[dim]  Check the hostname/IP and try again.[/dim]\n")
        sys.exit(1)

    console.print(f"[green]  ✔  Resolved → [bold]{ip}[/bold]  ({hostname})[/green]")

    # ── Step 3: Host liveness check ──────────────────────────────────────────
    console.print(f"[dim]  Checking host liveness...[/dim]")
    is_up, method = is_host_up(ip, timeout=timeout * 2)
    status = "[green]UP[/green]" if is_up else "[yellow]UNKNOWN[/yellow]"
    console.print(f"  Host status: {status}  [dim]({method})[/dim]")
    console.print()

    # ── Step 4: Display config ────────────────────────────────────────────────
    ports = PORT_PROFILES[profile]
    print_scan_config(target, ip, hostname, profile, os_detect, len(ports))

    # ── Step 5: Port scan with real TCP connects ──────────────────────────────
    console.print(
        f"[dim]  Scanning [bold]{len(ports)}[/bold] ports "
        f"(timeout={timeout}s, threads={min(100, len(ports))})...[/dim]\n"
    )

    open_ports: list[dict] = []
    scanned     = 0
    start_time  = time.time()

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, style="cyan", complete_style="bold cyan"),
        TextColumn("[bold white]{task.completed}/{task.total}"),
        TextColumn("[dim]{task.percentage:>3.0f}%[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Scanning ports...", total=len(ports))

        def on_port_done(port: int, result):
            nonlocal scanned
            scanned += 1
            if result:
                open_ports.append(result)
                progress.update(
                    task,
                    description=f"[bold green]Found: {result['service']} on {port}[/bold green]"
                )
            progress.advance(task)

        run_port_scan(
            ip=ip,
            ports=ports,
            timeout=timeout,
            max_threads=min(100, len(ports)),
            progress_callback=on_port_done,
        )

    duration = time.time() - start_time
    console.print()

    # ── Step 6: OS detection ──────────────────────────────────────────────────
    os_name = None
    if os_detect:
        console.print("[dim]  Detecting OS...[/dim]")
        open_port_nums = [p["port"] for p in open_ports]
        os_name = detect_os(ip, open_ports=open_port_nums)
        console.print(f"[green]  OS → {os_name}[/green]\n")

    # ── Step 7: Display results ────────────────────────────────────────────────
    print_results(open_ports, target, ip, hostname, os_name, duration, profile)

    # ── Step 8: Save report (optional) ────────────────────────────────────────
    if output:
        save_report(open_ports, target, ip, hostname, os_name, duration, profile, output)


# ── Interactive mode ──────────────────────────────────────────────────────────

def interactive_mode() -> dict:
    """Prompt the user for all scan parameters interactively."""
    console.print(Panel(
        "[bold white]Interactive Scan Configuration[/bold white]\n"
        "[dim]Press Enter to accept defaults shown in brackets.[/dim]",
        border_style="cyan", padding=(1, 2),
    ))
    console.print()

    # Target
    target = ""
    while not target.strip():
        target = console.input("[cyan]  Target IP or Hostname[/cyan] ❯ ").strip()
        if not target:
            console.print("[red]  Target cannot be empty.[/red]")

    # Profile
    console.print()
    console.print("  Scan profiles:")
    console.print("    [bold cyan]1[/bold cyan] · Quick    — 20 common ports        [dim](~5 seconds)[/dim]")
    console.print("    [bold cyan]2[/bold cyan] · Standard — 64 ports               [dim](~15 seconds)[/dim]  ← recommended")
    console.print("    [bold cyan]3[/bold cyan] · Full     — All 1024 ports          [dim](~30-60 seconds)[/dim]")
    console.print()
    choice = console.input("  [cyan]Profile[/cyan] [dim][2][/dim] ❯ ").strip() or "2"
    profile_map = {
        "1": "quick", "2": "standard", "3": "full",
        "quick": "quick", "standard": "standard", "full": "full",
    }
    profile = profile_map.get(choice, "standard")

    # OS detection
    console.print()
    os_input = console.input(
        "  [cyan]Enable OS detection?[/cyan] [dim][Y/n][/dim] ❯ "
    ).strip().lower()
    os_detect = os_input not in ("n", "no")

    # Timeout
    console.print()
    to_input = console.input(
        "  [cyan]TCP timeout per port (seconds)[/cyan] [dim][1.0][/dim] ❯ "
    ).strip() or "1.0"
    try:
        timeout = float(to_input)
        timeout = max(0.2, min(timeout, 10.0))  # Clamp between 0.2 and 10 seconds
    except ValueError:
        timeout = 1.0

    # Output file
    console.print()
    out_file = console.input(
        "  [cyan]Save report to file?[/cyan] [dim](leave blank to skip)[/dim] ❯ "
    ).strip() or None

    return {
        "target":    target,
        "profile":   profile,
        "os_detect": os_detect,
        "timeout":   timeout,
        "output":    out_file,
    }


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="netscan",
        description="NetScan v4.0 — Network Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              # Interactive mode
  python main.py -t 192.168.1.1              # Standard scan
  python main.py -t 192.168.1.1 -p quick    # Quick (20 ports)
  python main.py -t 192.168.1.1 -p full     # Full 1024-port scan
  python main.py -t scanme.nmap.org --no-os # Skip OS detection
  python main.py -t 192.168.1.1 -o rep.txt  # Save report
  python main.py -t 10.0.0.1 --timeout 2.0  # Slower timeout (unstable nets)

⚠  Only scan hosts you own or have explicit written permission to test.
        """,
    )
    parser.add_argument("-t", "--target",
                        help="Target IP address or hostname")
    parser.add_argument("-p", "--profile",
                        choices=["quick", "standard", "full"],
                        default="standard",
                        help="Scan profile (default: standard)")
    parser.add_argument("--no-os",
                        action="store_true",
                        help="Disable OS detection")
    parser.add_argument("-o", "--output",
                        help="Save text report to file (e.g. report.txt)")
    parser.add_argument("--timeout",
                        type=float,
                        default=1.0,
                        help="TCP connect timeout per port in seconds (default: 1.0)")
    parser.add_argument("--version",
                        action="version",
                        version="NetScan 4.0.0")

    args = parser.parse_args()

    if args.target:
        run_scan(
            target    = args.target,
            profile   = args.profile,
            os_detect = not args.no_os,
            output    = args.output,
            timeout   = args.timeout,
        )
    else:
        # No target given — launch interactive mode
        cfg = interactive_mode()
        console.print()
        run_scan(**cfg)


if __name__ == "__main__":
    main()
