"""
The pentest methodology knowledge base — Sentinel's "training".

This module encodes an OSCP/CTF-grade Linux methodology as data: the phase order,
the per-service enumeration playbook, quick-win checks, and default-credential
lists. The deterministic engine walks it directly; the LLM brain receives a
summary of it as grounding. Editing this file is how you teach Sentinel new tricks.

Command templates use these placeholders: {ip} {port} {url} {domain} {wordlist}
{scheme}. They are rendered by the tool layer, never by a shell string-eval, and
{ip}/{domain} are validated before substitution.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# High-level phases, in order.
# ---------------------------------------------------------------------------
PHASES = [
    ("recon",        "Discover open TCP/UDP ports and identify services + versions."),
    ("enumerate",    "Deep-enumerate each discovered service for attack surface."),
    ("identify",     "Map versions/creds/bugs to concrete vulnerabilities (searchsploit, CVEs)."),
    ("foothold",     "Exploit a vulnerability or weak creds to get an initial shell."),
    ("privesc",      "Enumerate the shell and escalate to root (Sentinel privesc engine)."),
    ("loot",         "Locate flags (user.txt/root.txt), creds, and sensitive data."),
]

# ---------------------------------------------------------------------------
# Recon: how to discover ports.
# ---------------------------------------------------------------------------
RECON_STEPS = [
    {
        "name": "tcp_all_ports",
        "tool": "nmap",
        "cmd": "nmap -p- --min-rate 2000 -T4 -Pn -oX - {ip}",
        "why": "Fast full-range TCP sweep to find every open port.",
    },
    {
        "name": "tcp_service_scan",
        "tool": "nmap",
        # {port} is filled with the comma-list of open ports from step 1.
        "cmd": "nmap -sV -sC -Pn -p{port} -oX - {ip}",
        "why": "Service/version detection + default NSE scripts on open ports.",
    },
    {
        "name": "udp_top",
        "tool": "nmap",
        "cmd": "nmap -sU --top-ports 50 -Pn -oX - {ip}",
        "why": "Top UDP ports (SNMP/TFTP/DNS often only show here).",
    },
]

# ---------------------------------------------------------------------------
# Per-service enumeration playbook. Keyed by nmap service name; also matched by
# port via SERVICE_BY_PORT below. Each step: tool, command template, rationale,
# and whether it is 'safe' (read-only enum) or 'active' (noisier).
# ---------------------------------------------------------------------------
SERVICE_PLAYBOOK: dict[str, list[dict]] = {
    "http": [
        {"tool": "whatweb", "cmd": "whatweb -a3 {scheme}://{ip}:{port}",
         "why": "Fingerprint server, framework, CMS, and versions.", "kind": "safe"},
        {"tool": "curl", "cmd": "curl -sk {scheme}://{ip}:{port}/robots.txt",
         "why": "robots.txt often lists hidden paths.", "kind": "safe"},
        {"tool": "feroxbuster",
         "cmd": "feroxbuster -u {scheme}://{ip}:{port} -w {wordlist} -q -k -t 50 --no-state",
         "why": "Recursive content/directory discovery.", "kind": "active"},
        {"tool": "gobuster",
         "cmd": "gobuster dir -u {scheme}://{ip}:{port} -w {wordlist} -q -k -t 50",
         "why": "Directory brute-force (fallback if no feroxbuster).", "kind": "active"},
        {"tool": "gobuster",
         "cmd": "gobuster vhost -u {scheme}://{ip}:{port} -w {wordlist} -q --append-domain",
         "why": "Virtual-host discovery (many CTF boxes hide sites behind vhosts).",
         "kind": "active"},
        {"tool": "nikto", "cmd": "nikto -host {scheme}://{ip}:{port} -maxtime 120s",
         "why": "Known-vuln and misconfig scanner.", "kind": "active"},
    ],
    "smb": [
        {"tool": "enum4linux-ng", "cmd": "enum4linux-ng -A {ip}",
         "why": "Comprehensive SMB/NetBIOS enumeration (users, shares, policy).", "kind": "safe"},
        {"tool": "smbmap", "cmd": "smbmap -H {ip}",
         "why": "List shares and access levels (null session).", "kind": "safe"},
        {"tool": "smbclient", "cmd": "smbclient -N -L //{ip}/",
         "why": "Anonymous share listing.", "kind": "safe"},
    ],
    "ftp": [
        {"tool": "nmap", "cmd": "nmap -p{port} --script ftp-anon,ftp-syst -Pn -oX - {ip}",
         "why": "Check anonymous login and FTP system info.", "kind": "safe"},
    ],
    "ssh": [
        {"tool": "nmap", "cmd": "nmap -p{port} --script ssh2-enum-algos,ssh-auth-methods -Pn -oX - {ip}",
         "why": "Banner, algorithms, and permitted auth methods.", "kind": "safe"},
    ],
    "dns": [
        {"tool": "dig", "cmd": "dig axfr @{ip} {domain}",
         "why": "Attempt a DNS zone transfer.", "kind": "safe"},
    ],
    "snmp": [
        {"tool": "snmpwalk", "cmd": "snmpwalk -v2c -c public {ip}",
         "why": "Walk the MIB with the default 'public' community string.", "kind": "safe"},
    ],
    "nfs": [
        {"tool": "showmount", "cmd": "showmount -e {ip}",
         "why": "List NFS exports (look for no_root_squash / world-mountable).", "kind": "safe"},
    ],
    "ldap": [
        {"tool": "nmap", "cmd": "nmap -p{port} --script ldap-search,ldap-rootdse -Pn -oX - {ip}",
         "why": "Dump the LDAP root DSE and naming contexts.", "kind": "safe"},
    ],
    "mysql": [
        {"tool": "nmap", "cmd": "nmap -p{port} --script mysql-info,mysql-empty-password -Pn -oX - {ip}",
         "why": "Server info and empty-password root check.", "kind": "safe"},
    ],
    "redis": [
        {"tool": "redis-cli", "cmd": "redis-cli -h {ip} -p {port} info",
         "why": "Unauthenticated Redis is a common RCE/keys foothold.", "kind": "safe"},
    ],
    "rpc": [
        {"tool": "rpcclient", "cmd": "rpcclient -U '' -N {ip} -c enumdomusers",
         "why": "Null-session RPC user enumeration.", "kind": "safe"},
    ],
}

# Map common ports to a playbook key when nmap's service name is ambiguous.
SERVICE_BY_PORT: dict[int, str] = {
    21: "ftp", 22: "ssh", 53: "dns", 111: "rpc", 139: "smb", 445: "smb",
    161: "snmp", 389: "ldap", 636: "ldap", 2049: "nfs", 3306: "mysql",
    6379: "redis", 80: "http", 443: "http", 8080: "http", 8000: "http",
    8443: "http", 8888: "http", 5000: "http",
}

HTTP_PORTS = {80, 443, 8080, 8000, 8443, 8888, 5000, 3000, 8081}
TLS_PORTS = {443, 8443}

# ---------------------------------------------------------------------------
# Wordlists (SecLists paths on Kali). Fallbacks handled by the tool layer.
# ---------------------------------------------------------------------------
WORDLISTS = {
    "dirs": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "dirs_small": "/usr/share/wordlists/dirb/common.txt",
    "vhosts": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "passwords": "/usr/share/wordlists/rockyou.txt",
    "users": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
}

# ---------------------------------------------------------------------------
# Quick wins: cheap checks that frequently yield a foothold on CTF boxes.
# ---------------------------------------------------------------------------
QUICK_WINS = [
    "Anonymous FTP login (ftp anonymous:anonymous).",
    "SMB null session / guest shares readable.",
    "Default web-app creds (admin:admin, admin:password, tomcat:tomcat).",
    "Exposed .git/ directory -> source disclosure (git-dumper).",
    "LFI in a 'page'/'file'/'lang' parameter -> /etc/passwd, log poisoning.",
    "Unauthenticated Redis -> write SSH key or webshell.",
    "Outdated CMS (WordPress/Drupal/Joomla) -> known RCE (searchsploit/wpscan).",
    "SUID/sudo GTFOBins for privesc (handled by Sentinel's privesc engine).",
]

# ---------------------------------------------------------------------------
# Default credentials worth spraying against discovered login surfaces.
# ---------------------------------------------------------------------------
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("root", "root"), ("root", "toor"), ("tomcat", "tomcat"),
    ("guest", "guest"), ("user", "user"), ("test", "test"),
    ("administrator", "administrator"), ("admin", ""), ("root", ""),
]

# ---------------------------------------------------------------------------
# Flag patterns to grep for once we have a shell (CTF conventions).
# ---------------------------------------------------------------------------
FLAG_HINTS = {
    "files": ["user.txt", "root.txt", "flag.txt", "proof.txt", "local.txt"],
    "regexes": [
        r"[0-9a-f]{32}",                     # HTB-style 32-hex flags
        r"(?:THM|FLAG|flag)\{[^}]+\}",       # THM/CTF flag{...}
        r"HTB\{[^}]+\}",
    ],
}


def playbook_for(service: str, port: int) -> list[dict]:
    """Return the enumeration steps for a service, resolving by name then port."""
    svc = (service or "").lower()
    if svc in SERVICE_PLAYBOOK:
        return SERVICE_PLAYBOOK[svc]
    if "http" in svc:
        return SERVICE_PLAYBOOK["http"]
    if "microsoft-ds" in svc or "netbios" in svc:
        return SERVICE_PLAYBOOK["smb"]
    key = SERVICE_BY_PORT.get(port)
    return SERVICE_PLAYBOOK.get(key, []) if key else []


def summary_for_llm() -> str:
    """A compact text digest of the methodology for the LLM system prompt."""
    lines = ["Linux CTF methodology phases:"]
    for name, desc in PHASES:
        lines.append(f"  {name}: {desc}")
    lines.append("Quick wins to always check:")
    lines += [f"  - {q}" for q in QUICK_WINS]
    return "\n".join(lines)
