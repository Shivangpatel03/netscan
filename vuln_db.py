"""
vuln_db.py — Built-in CVE Vulnerability Database
Maps TCP ports → service info, risk level, CVE ID, and description.
"""

# ── Vulnerability Database ───────────────────────────────────────────────────
# Each entry: port → { service, risk, cve, desc }
# risk levels: CRITICAL / HIGH / MEDIUM / LOW / INFO

VULN_DB: dict[int, dict] = {
    21:    {"service": "FTP",            "risk": "CRITICAL", "cve": "CVE-2011-2523",  "desc": "Backdoor command execution in vsftpd 2.3.4"},
    22:    {"service": "SSH",            "risk": "LOW",      "cve": None,             "desc": "Secure Shell — verify key-based auth is enforced"},
    23:    {"service": "Telnet",         "risk": "CRITICAL", "cve": "CVE-2011-4862",  "desc": "Cleartext credentials — replace with SSH immediately"},
    25:    {"service": "SMTP",           "risk": "MEDIUM",   "cve": "CVE-2020-7247",  "desc": "Open relay or VRFY user enumeration possible"},
    53:    {"service": "DNS",            "risk": "MEDIUM",   "cve": "CVE-2020-8617",  "desc": "DNS amplification attack vector possible"},
    69:    {"service": "TFTP",           "risk": "HIGH",     "cve": None,             "desc": "Trivial FTP — no authentication, file read/write"},
    79:    {"service": "Finger",         "risk": "MEDIUM",   "cve": None,             "desc": "User enumeration via finger protocol"},
    80:    {"service": "HTTP",           "risk": "HIGH",     "cve": "CVE-2021-41773", "desc": "Path traversal & RCE in Apache 2.4.49"},
    110:   {"service": "POP3",           "risk": "MEDIUM",   "cve": None,             "desc": "Mail retrieval — enforce STARTTLS"},
    111:   {"service": "RPCbind",        "risk": "HIGH",     "cve": "CVE-2017-8779",  "desc": "Memory exhaustion via crafted packets"},
    119:   {"service": "NNTP",           "risk": "LOW",      "cve": None,             "desc": "News protocol — usually unnecessary"},
    135:   {"service": "MSRPC",          "risk": "HIGH",     "cve": "CVE-2003-0352",  "desc": "MS RPC DCOM buffer overflow (Blaster worm)"},
    137:   {"service": "NetBIOS-NS",     "risk": "MEDIUM",   "cve": None,             "desc": "NetBIOS name service — information disclosure"},
    139:   {"service": "NetBIOS-SSN",    "risk": "CRITICAL", "cve": "CVE-2017-7494",  "desc": "SambaCry — arbitrary shared library RCE"},
    143:   {"service": "IMAP",           "risk": "LOW",      "cve": None,             "desc": "IMAP without STARTTLS exposes credentials"},
    161:   {"service": "SNMP",           "risk": "HIGH",     "cve": "CVE-2017-6736",  "desc": "SNMP default community string — network device takeover"},
    389:   {"service": "LDAP",           "risk": "MEDIUM",   "cve": None,             "desc": "LDAP without TLS — credential exposure"},
    443:   {"service": "HTTPS",          "risk": "LOW",      "cve": None,             "desc": "TLS enabled — verify cert expiry & cipher suites"},
    445:   {"service": "SMB",            "risk": "CRITICAL", "cve": "CVE-2017-0144",  "desc": "EternalBlue — SMBv1 unauthenticated RCE"},
    512:   {"service": "rexec",          "risk": "CRITICAL", "cve": None,             "desc": "Remote exec service — no encryption"},
    513:   {"service": "rlogin",         "risk": "CRITICAL", "cve": None,             "desc": "Remote login — allows passwordless access"},
    514:   {"service": "rsh",            "risk": "CRITICAL", "cve": None,             "desc": "r-services allow passwordless remote access"},
    515:   {"service": "LPD",            "risk": "MEDIUM",   "cve": "CVE-2001-0609",  "desc": "Line Printer Daemon — arbitrary command execution"},
    554:   {"service": "RTSP",           "risk": "MEDIUM",   "cve": None,             "desc": "Real-time streaming — camera/device access possible"},
    587:   {"service": "SMTP-MSA",       "risk": "LOW",      "cve": None,             "desc": "Mail submission — verify AUTH required"},
    631:   {"service": "IPP",            "risk": "MEDIUM",   "cve": "CVE-2019-8675",  "desc": "IPP printer — info disclosure & SSRF"},
    873:   {"service": "rsync",          "risk": "HIGH",     "cve": None,             "desc": "rsync without auth — full filesystem access"},
    993:   {"service": "IMAPS",          "risk": "LOW",      "cve": None,             "desc": "IMAP over SSL — verify certificate validity"},
    995:   {"service": "POP3S",          "risk": "LOW",      "cve": None,             "desc": "POP3 over SSL — verify certificate validity"},
    1080:  {"service": "SOCKS",          "risk": "HIGH",     "cve": None,             "desc": "SOCKS proxy — open proxy allows traffic pivoting"},
    1194:  {"service": "OpenVPN",        "risk": "LOW",      "cve": None,             "desc": "VPN endpoint — verify configuration hardening"},
    1433:  {"service": "MSSQL",          "risk": "HIGH",     "cve": "CVE-2020-0618",  "desc": "SQL Server RCE via crafted requests"},
    1521:  {"service": "Oracle-DB",      "risk": "HIGH",     "cve": "CVE-2012-1675",  "desc": "TNS Poison — man-in-the-middle attack"},
    1883:  {"service": "MQTT",           "risk": "HIGH",     "cve": None,             "desc": "MQTT broker — IoT message interception"},
    2049:  {"service": "NFS",            "risk": "HIGH",     "cve": None,             "desc": "NFS without auth exposes entire filesystem"},
    2181:  {"service": "ZooKeeper",      "risk": "HIGH",     "cve": None,             "desc": "ZooKeeper without auth — full cluster control"},
    2375:  {"service": "Docker-API",     "risk": "CRITICAL", "cve": "CVE-2019-5736",  "desc": "Docker daemon without TLS — host takeover"},
    2376:  {"service": "Docker-TLS",     "risk": "MEDIUM",   "cve": None,             "desc": "Docker TLS — verify cert-based auth"},
    3000:  {"service": "HTTP-Dev",       "risk": "MEDIUM",   "cve": None,             "desc": "Development server exposed — verify not in production"},
    3306:  {"service": "MySQL",          "risk": "HIGH",     "cve": "CVE-2016-6662",  "desc": "MySQL config file overwrite privilege escalation"},
    3389:  {"service": "RDP",            "risk": "CRITICAL", "cve": "CVE-2019-0708",  "desc": "BlueKeep — pre-auth RCE in Remote Desktop Services"},
    4369:  {"service": "Erlang-EPMD",    "risk": "HIGH",     "cve": None,             "desc": "Erlang port mapper — RabbitMQ cluster attack surface"},
    4444:  {"service": "Backdoor",       "risk": "CRITICAL", "cve": None,             "desc": "Metasploit default listener — system may be compromised"},
    4848:  {"service": "GlassFish",      "risk": "HIGH",     "cve": "CVE-2011-0807",  "desc": "GlassFish admin console — path traversal"},
    5000:  {"service": "Flask/UPnP",     "risk": "MEDIUM",   "cve": None,             "desc": "Development server or UPnP — verify not exposed"},
    5432:  {"service": "PostgreSQL",     "risk": "MEDIUM",   "cve": None,             "desc": "Ensure pg_hba.conf restricts all remote connections"},
    5672:  {"service": "AMQP",           "risk": "HIGH",     "cve": None,             "desc": "RabbitMQ without auth — message queue access"},
    5900:  {"service": "VNC",            "risk": "HIGH",     "cve": "CVE-2006-2369",  "desc": "VNC authentication bypass via null password"},
    5984:  {"service": "CouchDB",        "risk": "HIGH",     "cve": "CVE-2017-12636", "desc": "CouchDB admin party — unauthenticated RCE"},
    6379:  {"service": "Redis",          "risk": "CRITICAL", "cve": "CVE-2022-0543",  "desc": "Unauthenticated Redis — arbitrary Lua code execution"},
    6443:  {"service": "K8s-API",        "risk": "CRITICAL", "cve": None,             "desc": "Kubernetes API server — cluster takeover possible"},
    7001:  {"service": "WebLogic",       "risk": "CRITICAL", "cve": "CVE-2020-14882", "desc": "WebLogic RCE — unauthenticated console bypass"},
    7077:  {"service": "Spark-Master",   "risk": "HIGH",     "cve": None,             "desc": "Apache Spark without auth — code execution"},
    8080:  {"service": "HTTP-Alt",       "risk": "MEDIUM",   "cve": "CVE-2019-0232",  "desc": "Tomcat CGI servlet OS command injection"},
    8443:  {"service": "HTTPS-Alt",      "risk": "LOW",      "cve": None,             "desc": "Alternate HTTPS — verify TLS configuration"},
    8888:  {"service": "Jupyter",        "risk": "HIGH",     "cve": None,             "desc": "Jupyter Notebook without auth — arbitrary code exec"},
    9000:  {"service": "SonarQube/PHP",  "risk": "MEDIUM",   "cve": None,             "desc": "Dev service exposed — verify access control"},
    9090:  {"service": "Prometheus",     "risk": "HIGH",     "cve": None,             "desc": "Prometheus metrics — infrastructure data exposure"},
    9200:  {"service": "Elasticsearch",  "risk": "HIGH",     "cve": "CVE-2015-1427",  "desc": "Unauthenticated Elasticsearch — full data exposure"},
    9300:  {"service": "ES-Transport",   "risk": "HIGH",     "cve": None,             "desc": "Elasticsearch node transport — cluster access"},
    10000: {"service": "Webmin",         "risk": "CRITICAL", "cve": "CVE-2019-15107", "desc": "Webmin RCE — unauthenticated password reset"},
    11211: {"service": "Memcached",      "risk": "HIGH",     "cve": "CVE-2018-1000115","desc": "Memcached UDP — DDoS amplification & data leak"},
    15672: {"service": "RabbitMQ-Mgmt",  "risk": "HIGH",     "cve": None,             "desc": "RabbitMQ management UI — default credentials risk"},
    27017: {"service": "MongoDB",        "risk": "HIGH",     "cve": None,             "desc": "MongoDB without auth — full database exposure"},
    27018: {"service": "MongoDB-Shard",  "risk": "HIGH",     "cve": None,             "desc": "MongoDB shard without auth — full database exposure"},
    50000: {"service": "SAP-ICM",        "risk": "HIGH",     "cve": "CVE-2020-6287",  "desc": "SAP RECON — unauthenticated admin account creation"},
}

# ── Port scan profiles ────────────────────────────────────────────────────────
PORT_PROFILES: dict[str, list[int]] = {
    "quick": [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 3306, 3389, 5900, 6379, 8080, 8888, 9200, 27017,
    ],
    "standard": [
        21, 22, 23, 25, 53, 69, 79, 80, 110, 111, 119, 135, 137, 139, 143,
        161, 389, 443, 445, 512, 513, 514, 554, 587, 631, 873, 993, 995,
        1080, 1433, 1521, 1883, 2049, 2181, 2375, 2376, 3000, 3306, 3389,
        4369, 4444, 4848, 5000, 5432, 5672, 5900, 5984, 6379, 6443,
        7001, 8080, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211,
        15672, 27017, 27018, 50000,
    ],
    "full": list(range(1, 1025)),
}

# ── Risk color mapping (used by reporter) ────────────────────────────────────
RISK_STYLE: dict[str, tuple[str, str]] = {
    "CRITICAL": ("bold red",     "🔴"),
    "HIGH":     ("bold orange3", "🟠"),
    "MEDIUM":   ("bold yellow",  "🟡"),
    "LOW":      ("bold cyan",    "🔵"),
    "INFO":     ("bold blue",    "⚪"),
}
