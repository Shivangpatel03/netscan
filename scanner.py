"""
scanner.py — Real TCP Port Scanner with Banner Grabbing

Performs actual TCP connect scans using Python sockets.
No fake data — every result reflects a real live connection.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from vuln_db import VULN_DB


# ── Banner probes per service ────────────────────────────────────────────────
# Sent immediately after connecting to trigger a response banner
BANNER_PROBES: dict[int, bytes] = {
    21:    b"",                          # FTP sends banner automatically
    22:    b"",                          # SSH sends banner automatically
    23:    b"",                          # Telnet sends banner automatically
    25:    b"",                          # SMTP sends banner automatically
    53:    b"",                          # Skip UDP-oriented service
    80:    b"HEAD / HTTP/1.0\r\n\r\n",
    110:   b"",                          # POP3 sends banner automatically
    143:   b"",                          # IMAP sends banner automatically
    443:   b"",                          # TLS — skip raw probe
    445:   b"",                          # SMB — skip raw probe
    587:   b"",                          # SMTP-MSA sends banner
    873:   b"",                          # rsync sends banner
    1433:  b"",                          # MSSQL sends banner
    3306:  b"",                          # MySQL sends banner automatically
    5432:  b"",                          # PostgreSQL sends banner
    5900:  b"",                          # VNC sends banner
    6379:  b"INFO\r\n",                  # Redis INFO command
    7001:  b"HEAD / HTTP/1.0\r\n\r\n",
    8080:  b"HEAD / HTTP/1.0\r\n\r\n",
    8443:  b"",                          # TLS — skip raw probe
    8888:  b"HEAD / HTTP/1.0\r\n\r\n",
    9200:  b"GET / HTTP/1.0\r\n\r\n",    # Elasticsearch REST API
    10000: b"GET / HTTP/1.0\r\n\r\n",    # Webmin
    11211: b"stats\r\n",                 # Memcached
    27017: b"",                          # MongoDB sends banner
}

# Services where we skip banner grabbing (binary/TLS protocols)
SKIP_BANNER: set[int] = {443, 445, 8443, 3389, 5672, 6443}


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Connect to ip:port, optionally send a probe, and read the service banner.
    Returns the first meaningful line of the response, or 'unknown'.
    """
    if port in SKIP_BANNER:
        return ""

    probe = BANNER_PROBES.get(port, b"HEAD / HTTP/1.0\r\n\r\n")

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)

            # Send probe if we have one
            if probe:
                s.sendall(probe)

            # Read up to 1 KB
            try:
                raw = s.recv(1024)
            except socket.timeout:
                return "no banner"

            data = raw.decode("utf-8", errors="ignore").strip()

            # Return first non-empty, non-HTTP-status line
            for line in data.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Skip HTTP version lines like "HTTP/1.1 200 OK"
                if line.startswith("HTTP/"):
                    # For HTTP, return the Server header if present
                    continue
                return line[:100]

            # If all lines were HTTP headers, look for Server:
            for line in data.splitlines():
                if line.lower().startswith("server:"):
                    return line[7:].strip()[:100]

            return data[:100] if data else "no banner"

    except (ConnectionRefusedError, OSError, socket.timeout):
        return "unknown"
    except Exception:
        return "unknown"


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """
    Attempt a real TCP connect to ip:port.

    Returns a result dict if the port is OPEN, or None if closed/filtered.
    This is a real connection — if it returns a result, the port is genuinely open.
    """
    try:
        start = time.time()
        with socket.create_connection((ip, port), timeout=timeout):
            latency = round((time.time() - start) * 1000, 1)  # ms

        # Port is open — grab the service banner
        banner = grab_banner(ip, port, timeout=timeout + 1.0)

        # Look up vulnerability data
        db = VULN_DB.get(port)
        if db:
            return {
                "port":    port,
                "state":   "open",
                "service": db["service"],
                "banner":  banner or "—",
                "risk":    db["risk"],
                "cve":     db["cve"],
                "desc":    db["desc"],
                "latency": latency,
            }
        else:
            # Port is open but not in our vulnerability database
            try:
                svc_name = socket.getservbyport(port, "tcp")
            except OSError:
                svc_name = "unknown"
            return {
                "port":    port,
                "state":   "open",
                "service": svc_name,
                "banner":  banner or "—",
                "risk":    "INFO",
                "cve":     None,
                "desc":    "Open port — service not in vulnerability database",
                "latency": latency,
            }

    except (ConnectionRefusedError, socket.timeout, OSError):
        return None  # Port is closed or filtered — this is the normal case
    except Exception:
        return None


def run_port_scan(
    ip: str,
    ports: list[int],
    timeout: float = 1.0,
    max_threads: int = 100,
    progress_callback=None,
) -> list[dict]:
    """
    Scan a list of ports on ip using a thread pool.

    Args:
        ip:                Target IP address
        ports:             List of port numbers to scan
        timeout:           TCP connect timeout per port (seconds)
        max_threads:       Maximum concurrent threads
        progress_callback: Optional callable(port, result) called after each port

    Returns:
        List of open port result dicts, sorted by port number.
    """
    open_ports: list[dict] = []
    workers = min(max_threads, len(ports))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port   = future_to_port[future]
            result = future.result()

            if result:
                open_ports.append(result)

            if progress_callback:
                progress_callback(port, result)

    return sorted(open_ports, key=lambda x: x["port"])
