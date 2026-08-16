"""
The enumeration data model.

A :class:`Finding` is one atomic fact discovered on the target host — a SUID
binary, a sudo rule, a writable sensitive file, a group membership. The
enumerator turns raw command output into Findings; the rule engine and the LLM
reasoner both consume them.

Collection and analysis are decoupled through JSON (see :func:`dump` / :func:`load`),
exactly like the ad-pathfinder and ssti-exploiter projects — collect once on the
target, analyse offline (and test) anywhere.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict


# Finding categories the rest of the toolkit understands.
CATEGORIES = {
    "user",       # whoami / id output
    "os",         # kernel, distro
    "sudo",       # a `sudo -l` entry
    "suid",       # a SUID binary path
    "sgid",       # a SGID binary path
    "cap",        # a file capability (getcap line)
    "cron",       # a cron entry / script
    "writable",   # a writable sensitive file/dir (key says which)
    "group",      # an interesting group membership
    "nfs",        # an /etc/exports line
    "env",        # sudo env_keep / LD_PRELOAD etc.
    "path",       # a writable or unsafe $PATH element
}


@dataclass
class Finding:
    category: str            # one of CATEGORIES
    value: str               # the primary datum, e.g. "/usr/bin/find"
    key: str = ""            # optional sub-type, e.g. "etc_passwd" for writable
    detail: str = ""         # human context, e.g. "NOPASSWD" or "world-writable"
    raw: str = ""            # the raw source line, for the LLM / audit

    def __str__(self) -> str:
        bits = [f"{self.category}:{self.value}"]
        if self.key:
            bits.append(f"({self.key})")
        if self.detail:
            bits.append(f"- {self.detail}")
        return " ".join(bits)


def dump(findings: list[Finding], path: str, meta: dict | None = None) -> None:
    data = {"meta": meta or {}, "findings": [asdict(f) for f in findings]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def load(path: str) -> tuple[list[Finding], dict]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    findings = [
        Finding(
            category=f["category"], value=f["value"],
            key=f.get("key", ""), detail=f.get("detail", ""), raw=f.get("raw", ""),
        )
        for f in data.get("findings", [])
    ]
    return findings, data.get("meta", {})


def by_category(findings: list[Finding], category: str) -> list[Finding]:
    return [f for f in findings if f.category == category]
