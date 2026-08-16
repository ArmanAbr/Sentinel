"""
Tool-adapter layer.

Wraps external pentest CLIs (nmap, ffuf, whatweb, ...) in a uniform, *safe*
runner: command templates are tokenised and each placeholder is substituted with
a **validated** value, then executed via argv (never `shell=True`), so a crafted
target/domain can't inject a shell command.

Availability is detected with `shutil.which`; missing tools are reported (with an
install hint) and skipped rather than crashing the engine.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field

# --- target validation -----------------------------------------------------
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*$")
_URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-:]+(?:/[^\s]*)?$")


def valid_ip_or_host(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(value))


def _validate_substitutions(subs: dict) -> None:
    if "ip" in subs and not valid_ip_or_host(str(subs["ip"])):
        raise ValueError(f"Refusing unsafe target value: {subs['ip']!r}")
    if "domain" in subs and subs["domain"] and not _HOSTNAME_RE.match(str(subs["domain"])):
        raise ValueError(f"Refusing unsafe domain value: {subs['domain']!r}")
    if "url" in subs and subs["url"] and not _URL_RE.match(str(subs["url"])):
        raise ValueError(f"Refusing unsafe url value: {subs['url']!r}")
    if "port" in subs:
        # allow a single port or a comma list of ports
        for p in str(subs["port"]).split(","):
            if p and not p.isdigit():
                raise ValueError(f"Refusing unsafe port value: {subs['port']!r}")
    if "scheme" in subs and subs["scheme"] not in ("http", "https"):
        raise ValueError(f"Refusing unsafe scheme: {subs['scheme']!r}")


# Install hints per tool (Kali/apt names) for the "missing tool" message.
INSTALL_HINTS = {
    "nmap": "apt install nmap",
    "whatweb": "apt install whatweb",
    "feroxbuster": "apt install feroxbuster",
    "gobuster": "apt install gobuster",
    "ffuf": "apt install ffuf",
    "nikto": "apt install nikto",
    "enum4linux-ng": "pipx install enum4linux-ng  (or apt install enum4linux)",
    "smbmap": "apt install smbmap",
    "smbclient": "apt install smbclient",
    "snmpwalk": "apt install snmp",
    "showmount": "apt install nfs-common",
    "rpcclient": "apt install samba-common-bin",
    "redis-cli": "apt install redis-tools",
    "dig": "apt install dnsutils",
    "searchsploit": "apt install exploitdb",
    "curl": "apt install curl",
}


@dataclass
class ToolResult:
    tool: str
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    ok: bool = True
    error: str = ""

    @property
    def output(self) -> str:
        return self.stdout + ("\n" + self.stderr if self.stderr else "")


def available(tool: str) -> bool:
    return shutil.which(tool) is not None


def render(cmd_template: str, subs: dict) -> list[str]:
    """Tokenise a command template and substitute validated placeholders,
    returning an argv list. Raises ValueError on unsafe substitutions."""
    _validate_substitutions(subs)
    tokens = shlex.split(cmd_template)
    out = []
    for tok in tokens:
        for key, val in subs.items():
            tok = tok.replace("{" + key + "}", str(val))
        out.append(tok)
    return out


def run(cmd_template: str, subs: dict, timeout: int = 300,
        verbose: bool = False) -> ToolResult:
    """Render and execute a tool command safely (no shell)."""
    try:
        argv = render(cmd_template, subs)
    except ValueError as exc:
        return ToolResult(tool="?", argv=[], returncode=-1, stdout="", stderr=str(exc),
                          duration=0.0, ok=False, error=str(exc))

    tool = argv[0] if argv else "?"
    if not available(tool):
        hint = INSTALL_HINTS.get(tool, f"install {tool}")
        return ToolResult(tool=tool, argv=argv, returncode=127, stdout="", stderr="",
                          duration=0.0, ok=False, error=f"{tool} not installed ({hint})")

    if verbose:
        print(f"    [run] {' '.join(argv)}")
    start = time.time()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return ToolResult(tool=tool, argv=argv, returncode=proc.returncode,
                          stdout=proc.stdout, stderr=proc.stderr,
                          duration=time.time() - start, ok=True)
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        return ToolResult(tool=tool, argv=argv, returncode=-1, stdout=partial,
                          stderr=f"timed out after {timeout}s", duration=timeout,
                          ok=True, error="timeout")
    except Exception as exc:  # noqa: BLE001
        return ToolResult(tool=tool, argv=argv, returncode=-1, stdout="", stderr=str(exc),
                          duration=time.time() - start, ok=False, error=str(exc))
