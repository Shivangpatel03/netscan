"""
os_detect.py — Robust OS Detection (6 methods, never fails silently)

Methods tried in priority order:
  1. SSH banner    — most accurate, reveals exact distro & version
  2. HTTP headers  — Server: header reveals IIS (Windows) vs Apache/nginx (Linux)
  3. FTP banner    — many FTP daemons include OS info
  4. SMTP banner   — Postfix/Sendmail banners often include hostname/OS hints
  5. Ping TTL      — Windows=~128, Linux=~64, Cisco=~255
  6. TCP port mix  — educated guess from which ports are open

If ALL methods fail, returns a human-friendly message instead of a raw error.
"""

import socket
import subprocess
import platform
import re
import sys


# ── TTL → OS mapping ──────────────────────────────────────────────────────────
# Routers decrement TTL by 1 per hop, so use generous ranges around
# the standard initial values: Windows=128, Linux/macOS=64, Cisco=255

def _os_from_ttl(ttl: int) -> str:
    if ttl >= 240:                    return f"Cisco / Network Device (TTL={ttl})"
    if 110 <= ttl <= 138:             return f"Windows (TTL={ttl})"
    if 54 <= ttl <= 75:               return f"Linux / macOS / FreeBSD (TTL={ttl})"
    if 28 <= ttl <= 35:               return f"Solaris / AIX (TTL={ttl})"
    if ttl > 138:                     return f"Network Device / Firewall (TTL={ttl})"
    if ttl > 75:                      return f"Windows (TTL={ttl})"   # high hop-count path
    return                                   f"Linux / Unix (TTL={ttl})"


# ── Method 1: Ping TTL ────────────────────────────────────────────────────────

def _ttl_via_ping(ip: str) -> int | None:
    """
    Send one ICMP ping and parse the TTL from the response.
    Handles Windows, Linux, and macOS ping output formats.
    """
    os_name = platform.system()

    # Build the right command for each platform
    if os_name == "Windows":
        cmd = ["ping", "-n", "1", "-w", "2000", ip]
    elif os_name == "Darwin":  # macOS
        cmd = ["ping", "-c", "1", "-W", "2000", ip]
    else:                      # Linux
        cmd = ["ping", "-c", "1", "-W", "2", ip]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=6,
        )
        output = result.stdout + result.stderr

        # Matches: ttl=64  TTL=128  ttl: 64  TTL : 128
        match = re.search(r"\bttl[=:\s]+(\d+)", output, re.IGNORECASE)
        if match:
            return int(match.group(1))

    except FileNotFoundError:
        pass   # ping not in PATH (rare but possible in containers)
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return None


# ── Method 2: SSH banner ──────────────────────────────────────────────────────

def _os_from_ssh(ip: str, port: int = 22, timeout: float = 3.0) -> str | None:
    """
    Read the SSH banner and extract OS/distro information.

    Common banner formats:
      SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
      SSH-2.0-OpenSSH_7.4
      SSH-2.0-OpenSSH_8.0 FreeBSD-20200214
      SSH-2.0-OpenSSH_for_Windows_8.1
      SSH-2.0-libssh_0.9.6   (routers, embedded)
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            raw = s.recv(256)
            banner = raw.decode("utf-8", errors="ignore").strip()

            if not banner.upper().startswith("SSH"):
                return None

            b = banner.lower()

            if "ubuntu"  in b: return f"Ubuntu Linux  [{banner[:70]}]"
            if "debian"  in b: return f"Debian Linux  [{banner[:70]}]"
            if "centos"  in b: return f"CentOS Linux  [{banner[:70]}]"
            if "rhel"    in b: return f"Red Hat Enterprise Linux  [{banner[:70]}]"
            if "fedora"  in b: return f"Fedora Linux  [{banner[:70]}]"
            if "raspbian"in b: return f"Raspberry Pi OS  [{banner[:70]}]"
            if "alpine"  in b: return f"Alpine Linux  [{banner[:70]}]"
            if "freebsd" in b: return f"FreeBSD  [{banner[:70]}]"
            if "netbsd"  in b: return f"NetBSD  [{banner[:70]}]"
            if "openbsd" in b: return f"OpenBSD  [{banner[:70]}]"
            if "windows" in b or "microsoft" in b or "for_windows" in b:
                                return f"Windows (OpenSSH built-in)  [{banner[:70]}]"
            if "cisco"   in b: return f"Cisco IOS / IOS-XE  [{banner[:70]}]"
            if "juniper" in b: return f"Juniper JunOS  [{banner[:70]}]"
            if "libssh"  in b: return f"Embedded Linux / Network Device  [{banner[:70]}]"

            # OpenSSH with no distro tag — likely generic Linux
            if "openssh" in b:
                return f"Linux / Unix — OpenSSH  [{banner[:70]}]"

            return f"Unix-like  [{banner[:70]}]"

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


# ── Method 3: HTTP Server header ──────────────────────────────────────────────

def _os_from_http(ip: str, port: int = 80, timeout: float = 3.0) -> str | None:
    """
    Send an HTTP HEAD request and parse the Server: response header.

    Example Server headers:
      Server: Apache/2.4.41 (Ubuntu)
      Server: Microsoft-IIS/10.0
      Server: nginx/1.18.0 (Ubuntu)
      Server: Apache/2.4.6 (CentOS)
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            request = (
                f"HEAD / HTTP/1.0\r\n"
                f"Host: {ip}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            s.sendall(request.encode())
            response = s.recv(2048).decode("utf-8", errors="ignore")

            server_header = ""
            x_powered_by  = ""

            for line in response.splitlines():
                ll = line.lower()
                if ll.startswith("server:"):
                    server_header = line[7:].strip()
                if ll.startswith("x-powered-by:"):
                    x_powered_by = line[13:].strip()

            # Combine for analysis
            combined = (server_header + " " + x_powered_by).lower()

            if not combined.strip():
                return None

            if "iis"      in combined or "microsoft-iis" in combined:
                return f"Windows Server (IIS)  [Server: {server_header}]"
            if "windows"  in combined:
                return f"Windows  [Server: {server_header}]"
            if "ubuntu"   in combined:
                return f"Ubuntu Linux  [Server: {server_header}]"
            if "debian"   in combined:
                return f"Debian Linux  [Server: {server_header}]"
            if "centos"   in combined:
                return f"CentOS Linux  [Server: {server_header}]"
            if "fedora"   in combined:
                return f"Fedora Linux  [Server: {server_header}]"
            if "red hat"  in combined or "rhel" in combined:
                return f"Red Hat Linux  [Server: {server_header}]"
            if "freebsd"  in combined:
                return f"FreeBSD  [Server: {server_header}]"
            if "synology" in combined:
                return f"Synology NAS (Linux)  [Server: {server_header}]"
            if "dd-wrt"   in combined or "openwrt" in combined:
                return f"OpenWRT / DD-WRT (Router)  [Server: {server_header}]"
            if "apache"   in combined:
                return f"Linux / Unix (Apache)  [Server: {server_header}]"
            if "nginx"    in combined:
                return f"Linux / Unix (nginx)  [Server: {server_header}]"
            if "lighttpd" in combined:
                return f"Linux (lighttpd)  [Server: {server_header}]"

            # At minimum we have a server header — better than nothing
            return f"Unknown OS  [Server: {server_header}]"

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


# ── Method 4: FTP banner ──────────────────────────────────────────────────────

def _os_from_ftp(ip: str, port: int = 21, timeout: float = 3.0) -> str | None:
    """
    Read the FTP 220 banner — many include OS info.

    Examples:
      220 (vsFTPd 3.0.3)
      220 ProFTPD 1.3.5 Server (Debian) [ip]
      220 Microsoft FTP Service
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(512).decode("utf-8", errors="ignore").strip()

            if not banner.startswith("220"):
                return None

            b = banner.lower()
            if "microsoft" in b or "windows" in b:
                return f"Windows (Microsoft FTP)  [{banner[:80]}]"
            if "debian"    in b: return f"Debian Linux (FTP)  [{banner[:80]}]"
            if "ubuntu"    in b: return f"Ubuntu Linux (FTP)  [{banner[:80]}]"
            if "centos"    in b: return f"CentOS Linux (FTP)  [{banner[:80]}]"
            if "vsftpd"    in b: return f"Linux (vsftpd)  [{banner[:80]}]"
            if "proftpd"   in b: return f"Linux (ProFTPD)  [{banner[:80]}]"
            if "freebsd"   in b: return f"FreeBSD (FTP)  [{banner[:80]}]"

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


# ── Method 5: SMTP banner ─────────────────────────────────────────────────────

def _os_from_smtp(ip: str, port: int = 25, timeout: float = 3.0) -> str | None:
    """
    Read SMTP 220 banner — Postfix/Sendmail banners hint at the OS.

    Examples:
      220 hostname ESMTP Postfix (Ubuntu)
      220 hostname Microsoft ESMTP MAIL Service
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(512).decode("utf-8", errors="ignore").strip()

            if not banner.startswith("220"):
                return None

            b = banner.lower()
            if "microsoft" in b or "exchange" in b:
                return f"Windows (Exchange/IIS SMTP)  [{banner[:80]}]"
            if "ubuntu"    in b: return f"Ubuntu Linux (Postfix)  [{banner[:80]}]"
            if "debian"    in b: return f"Debian Linux (Postfix)  [{banner[:80]}]"
            if "centos"    in b: return f"CentOS Linux (Postfix/Sendmail)  [{banner[:80]}]"
            if "postfix"   in b: return f"Linux (Postfix SMTP)  [{banner[:80]}]"
            if "sendmail"  in b: return f"Unix (Sendmail)  [{banner[:80]}]"

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


# ── Method 6: Port-mix heuristic ─────────────────────────────────────────────

def _os_from_open_ports(open_ports: set[int]) -> str | None:
    """
    Make an educated OS guess purely from which ports are open.
    Not highly accurate but gives something useful when all else fails.
    """
    if not open_ports:
        return None

    # Strong Windows indicators
    windows_ports = {135, 139, 445, 3389, 5985, 5986}  # RPC, SMB, RDP, WinRM
    if len(open_ports & windows_ports) >= 2:
        return "Windows (inferred from open ports: RPC/SMB/RDP)"

    # Strong Linux indicators
    linux_ports = {22, 111, 2049}  # SSH, RPCbind, NFS
    if 22 in open_ports and len(open_ports & {111, 2049, 873, 6379}) >= 1:
        return "Linux (inferred from open ports: SSH + Linux services)"

    if 22 in open_ports and 3389 not in open_ports:
        return "Linux / Unix (SSH open, no RDP)"

    if 3389 in open_ports and 22 not in open_ports:
        return "Windows (RDP open, no SSH)"

    if 3389 in open_ports and 445 in open_ports:
        return "Windows (RDP + SMB open)"

    # Router / embedded device indicators
    router_ports = {23, 80, 443, 8080, 8443}
    if open_ports <= router_ports and len(open_ports) <= 3:
        return "Router / Embedded Device (inferred from port mix)"

    return None


# ── Public API ────────────────────────────────────────────────────────────────

def detect_os(ip: str, open_ports: list[int] | None = None) -> str:
    """
    Detect the OS of a remote host using 6 methods in priority order.

    Args:
        ip:         Target IP address (already resolved)
        open_ports: List of confirmed open port numbers from the scan

    Returns:
        A human-readable OS string — NEVER returns an error/exception,
        always falls back gracefully to a descriptive message.
    """
    ports = set(open_ports or [])

    # ── Method 1: SSH banner (most informative) ───────────────────────────────
    # Try SSH ports that are actually open first, then port 22 as default
    ssh_candidates = [p for p in [22, 2222, 22222] if p in ports]
    if not ssh_candidates and not ports:
        ssh_candidates = [22]  # blind probe if we have no port info

    for port in ssh_candidates:
        result = _os_from_ssh(ip, port=port)
        if result:
            return result

    # ── Method 2: HTTP on all open HTTP ports ─────────────────────────────────
    http_candidates = [p for p in [80, 8080, 8000, 8888, 8008, 8888, 3000] if p in ports]
    if not http_candidates and not ports:
        http_candidates = [80]  # blind probe

    for port in http_candidates[:3]:  # Try up to 3 HTTP ports
        result = _os_from_http(ip, port=port)
        if result:
            return result

    # ── Method 3: FTP banner ──────────────────────────────────────────────────
    if 21 in ports or not ports:
        result = _os_from_ftp(ip)
        if result:
            return result

    # ── Method 4: SMTP banner ─────────────────────────────────────────────────
    if 25 in ports or 587 in ports or not ports:
        smtp_port = 25 if 25 in ports else (587 if 587 in ports else 25)
        result = _os_from_smtp(ip, port=smtp_port)
        if result:
            return result

    # ── Method 5: Ping TTL ─────────────────────────────────────────────────────
    ttl = _ttl_via_ping(ip)
    if ttl:
        return _os_from_ttl(ttl)

    # ── Method 6: Port-mix heuristic ──────────────────────────────────────────
    if ports:
        result = _os_from_open_ports(ports)
        if result:
            return result

    # ── Final fallback — informative, not just "Unknown" ─────────────────────
    if ports:
        return (
            f"Could not detect OS — host responded on {len(ports)} port(s) "
            f"({', '.join(str(p) for p in sorted(ports)[:5])}{'...' if len(ports) > 5 else ''}). "
            f"ICMP ping may be blocked; SSH/HTTP not open or returned no banner."
        )
    return (
        "Could not detect OS — no open ports found or host is not responding. "
        "Try a wider scan profile or increase --timeout."
    )
