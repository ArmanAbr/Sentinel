"""
Enumeration: collect facts from the target host.

The parse_* functions are **pure** (raw text in, Findings out) so they can be
unit-tested without any host. The :class:`Enumerator` runs the probe commands via
a pluggable *executor* — a callable ``(cmd: str) -> str`` — so the same logic
drives a local shell, an SSH session, or a replay of captured output.
"""

from __future__ import annotations

import shutil
import subprocess

from .findings import Finding

# Probe commands. Each returns text the matching parser understands.
PROBES: dict[str, str] = {
    "id":     "id 2>/dev/null; echo '---'; whoami 2>/dev/null",
    "kernel": "uname -a 2>/dev/null; echo '---'; cat /etc/os-release 2>/dev/null",
    "sudo":   "sudo -n -l 2>/dev/null",
    "suid":   "find / -perm -4000 -type f 2>/dev/null",
    "sgid":   "find / -perm -2000 -type f 2>/dev/null",
    "caps":   "getcap -r / 2>/dev/null",
    "cron":   "cat /etc/crontab 2>/dev/null; echo '---'; ls -la /etc/cron.d/ 2>/dev/null",
    "writable": (
        "for f in /etc/passwd /etc/shadow /etc/sudoers; do "
        "[ -w \"$f\" ] && echo \"$f\"; done; "
        "find /etc/cron* -writable 2>/dev/null"
    ),
    "groups": "id -Gn 2>/dev/null",
    "nfs":    "cat /etc/exports 2>/dev/null",
    "env":    "sudo -n -l 2>/dev/null | grep -i env_keep",
    "path":   "echo \"$PATH\"",
}


# --- pure parsers ----------------------------------------------------------
def parse_id(text: str) -> list[Finding]:
    who = text.split("---")[-1].strip() if "---" in text else ""
    line = text.splitlines()[0].strip() if text.strip() else ""
    out = []
    if line:
        out.append(Finding("user", who or "?", key="id", detail=line, raw=line))
    return out


def parse_kernel(text: str) -> list[Finding]:
    out: list[Finding] = []
    parts = text.split("---")
    uname = parts[0].strip()
    if uname:
        # uname -a -> "Linux host 5.4.0-42-generic #46 ..."
        tokens = uname.split()
        version = tokens[2] if len(tokens) >= 3 else uname
        out.append(Finding("os", version, key="kernel", raw=uname))
    if len(parts) > 1:
        for ln in parts[1].splitlines():
            if ln.startswith("PRETTY_NAME="):
                distro = ln.split("=", 1)[1].strip().strip('"')
                out.append(Finding("os", distro, key="distro", raw=ln))
    return out


def parse_sudo(text: str) -> list[Finding]:
    out: list[Finding] = []
    for ln in text.splitlines():
        s = ln.strip()
        # sudo -l entries look like: (root) NOPASSWD: /usr/bin/find
        if s.startswith("(") and ":" in s:
            nopasswd = "NOPASSWD" in s.upper()
            out.append(Finding("sudo", s, key="rule",
                               detail="NOPASSWD" if nopasswd else "", raw=ln))
        elif "(ALL : ALL) ALL" in s or "(ALL) ALL" in s:
            out.append(Finding("sudo", s, key="all", detail="full sudo", raw=ln))
    return out


def _parse_paths(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith("/")]


def parse_suid(text: str) -> list[Finding]:
    return [Finding("suid", p, raw=p) for p in _parse_paths(text)]


def parse_sgid(text: str) -> list[Finding]:
    return [Finding("sgid", p, raw=p) for p in _parse_paths(text)]


def parse_caps(text: str) -> list[Finding]:
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            continue
        # getcap: "/usr/bin/python3.8 cap_setuid=ep"  (older: "= cap_setuid+ep")
        path = s.split()[0]
        out.append(Finding("cap", path, key="capability", detail=s, raw=ln))
    return out


def parse_cron(text: str) -> list[Finding]:
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if s and not s.startswith("#") and (s[0].isdigit() or s.startswith("@") or "* *" in s):
            out.append(Finding("cron", s, key="entry", raw=ln))
    return out


def parse_writable(text: str) -> list[Finding]:
    out = []
    for ln in text.splitlines():
        p = ln.strip()
        if not p.startswith("/"):
            continue
        key = "other"
        if p == "/etc/passwd":
            key = "etc_passwd"
        elif p == "/etc/shadow":
            key = "etc_shadow"
        elif p == "/etc/sudoers":
            key = "sudoers"
        elif "cron" in p:
            key = "cron"
        out.append(Finding("writable", p, key=key, detail="writable by us", raw=ln))
    return out


INTERESTING_GROUPS = {"docker", "lxd", "lxc", "disk", "adm", "shadow", "sudo", "wheel"}


def parse_groups(text: str) -> list[Finding]:
    out = []
    for g in text.replace("\n", " ").split():
        if g in INTERESTING_GROUPS:
            out.append(Finding("group", g, raw=text.strip()))
    return out


def parse_nfs(text: str) -> list[Finding]:
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if s and not s.startswith("#") and "no_root_squash" in s:
            out.append(Finding("nfs", s, key="no_root_squash",
                               detail="no_root_squash export", raw=ln))
    return out


def parse_env(text: str) -> list[Finding]:
    out = []
    for ln in text.splitlines():
        s = ln.strip()
        if "LD_PRELOAD" in s or "LD_LIBRARY_PATH" in s:
            out.append(Finding("env", s, key="ld_preload", detail="env_keep dangerous", raw=ln))
    return out


def parse_path(text: str) -> list[Finding]:
    out = []
    for elem in text.strip().split(":"):
        e = elem.strip()
        # An empty element or any non-absolute entry (".", "bin", "./x") is
        # resolved relative to the CWD — the classic writable-PATH hijack vector.
        # Absolute dirs under world-writable trees (/tmp, /home) are unsafe too.
        relative = e == "" or not e.startswith("/")
        if relative or e.startswith("/tmp") or e.startswith("/home"):
            out.append(Finding("path", e or ".", key="unsafe_path",
                               detail="writable/relative PATH element", raw=text.strip()))
    return out


PARSERS = {
    "id": parse_id, "kernel": parse_kernel, "sudo": parse_sudo,
    "suid": parse_suid, "sgid": parse_sgid, "caps": parse_caps,
    "cron": parse_cron, "writable": parse_writable, "groups": parse_groups,
    "nfs": parse_nfs, "env": parse_env, "path": parse_path,
}


# --- executors -------------------------------------------------------------
def local_executor(cmd: str) -> str:
    """Run a probe in the local shell (for use ON a compromised Linux host)."""
    try:
        r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=60)
        return r.stdout + r.stderr
    except Exception as exc:  # noqa: BLE001
        return f"__EXEC_ERROR__: {exc}"


def ssh_executor(host: str, user: str, password: str = "", key: str = "", port: int = 22):
    """Return an executor that runs probes over SSH (needs paramiko)."""
    import paramiko  # imported lazily so offline analysis needs no dependency

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=port, username=user,
                   password=password or None, key_filename=key or None, timeout=15)

    def _exec(cmd: str) -> str:
        _in, out, err = client.exec_command(cmd, timeout=60)
        return out.read().decode(errors="replace") + err.read().decode(errors="replace")

    _exec.close = client.close  # type: ignore[attr-defined]
    return _exec


class Enumerator:
    def __init__(self, executor, verbose: bool = False) -> None:
        self.executor = executor
        self.verbose = verbose

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for name, cmd in PROBES.items():
            if self.verbose:
                print(f"    [probe] {name}")
            output = self.executor(cmd)
            if output.startswith("__EXEC_ERROR__"):
                if self.verbose:
                    print(f"        {output}")
                continue
            findings.extend(PARSERS[name](output))
        return findings

    @staticmethod
    def has_local_shell() -> bool:
        return shutil.which("bash") is not None
