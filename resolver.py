"""
resolver.py — Target Resolution & Host Liveness

Resolves hostnames to IPs, validates input, and checks if a host is up
using real TCP probes before launching a full scan.
"""

import socket
import ipaddress
from typing import Optional


def resolve_target(target: str) -> tuple[Optional[str], Optional[str]]:
    """
    Resolve a target (IP or hostname) to (ip, hostname).

    Returns:
        (ip, hostname) tuple — both None if resolution fails.

    Examples:
        resolve_target("192.168.1.1")   → ("192.168.1.1", "router.local")
        resolve_target("example.com")   → ("93.184.216.34", "example.com")
        resolve_target("bad-host")      → (None, None)
    """
    target = target.strip()

    # ── Case 1: already an IP address ────────────────────────────────────────
    try:
        ipaddress.ip_address(target)
        # Try reverse DNS for hostname
        try:
            hostname = socket.gethostbyaddr(target)[0]
        except (socket.herror, socket.gaierror):
            hostname = target
        return target, hostname

    except ValueError:
        pass  # Not an IP, try as hostname

    # ── Case 2: hostname — resolve to IP ─────────────────────────────────────
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except socket.gaierror:
        return None, None


def is_host_up(ip: str, timeout: float = 2.0) -> tuple[bool, str]:
    """
    Check if a host is up by attempting TCP connections to common ports.

    This is more reliable than ICMP ping (which may be blocked by firewalls).
    We try several ports — if ANY responds, the host is considered up.

    Returns:
        (is_up: bool, method: str)
        method describes which probe confirmed liveness.
    """
    probe_ports = [
        (80,  "HTTP"),
        (443, "HTTPS"),
        (22,  "SSH"),
        (445, "SMB"),
        (3389,"RDP"),
        (21,  "FTP"),
        (23,  "Telnet"),
        (25,  "SMTP"),
        (8080,"HTTP-Alt"),
    ]

    for port, name in probe_ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True, f"TCP/{port} ({name}) responded"
        except (ConnectionRefusedError, socket.timeout, OSError):
            continue

    # If no port responded, we still proceed (host may have all ports filtered
    # except the ones we'll actually scan, or ICMP ping may be disabled)
    return True, "no probe response — proceeding anyway (host may filter probes)"


def validate_target(target: str) -> tuple[bool, str]:
    """
    Basic input validation before attempting resolution.

    Returns:
        (is_valid: bool, error_message: str)
    """
    target = target.strip()

    if not target:
        return False, "Target cannot be empty."

    # Block obvious local-only or loopback targets in a warning only
    # (we still allow them — scanning localhost is legitimate)

    # Check for obviously bad input
    if " " in target:
        return False, "Target cannot contain spaces."

    if len(target) > 253:
        return False, "Target too long (max 253 characters)."

    return True, ""
