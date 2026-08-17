# Sentinel - Autonomous Privilege-Escalation Agent

Sentinel is an **AI-assisted privilege-escalation agent** for Linux. Drop it on (or
point it at) a low-privilege foothold and it will **enumerate** the host, **reason**
about the findings the way an OSCP-level pentester does, and **propose — or, when
authorized, execute — the exact next step toward root**, showing its chain of thought
along the way.

**In short:**

- **Dual-brain** privesc engine: a deterministic, offline GTFOBins/HackTricks rule
  engine that ranks ready-to-run escalation vectors (SUID, sudo, capabilities,
  dangerous groups, writable system files), plus an *optional* Claude LLM layer that
  re-prioritizes and combines findings.
- Includes `autopwn`, an authorization-gated engagement orchestrator that chains real
  Kali tools (nmap, feroxbuster, nikto, enum4linux-ng, searchsploit) into a
  prioritized foothold report.
- Safety-first: read-only by default, execution guarded behind explicit authorization
  flags, graceful degradation with no API key, and 18 offline tests.

--- 

## Two tools in one

| Command | What it does |
|---|---|
| **`autopwn.py <ip>`** | **Autonomous engagement engine** — give it a target IP and it runs the full external methodology: nmap recon → per-service enumeration → vuln identification → a prioritized report telling you how to get a foothold. |
| **`sentinel.py`** | **Privilege-escalation engine** — once you have a shell, enumerate the host and rank the paths to root. |

The intended flow is `autopwn.py` (get in) → `sentinel.py` (get root).

### autopwn quick start

```powershell
# See the FULL attack plan without touching the target (no tools needed):
py autopwn.py 10.10.10.5 --plan --active

# Live run (recon + safe read-only enumeration), authorized targets only:
py autopwn.py 10.10.10.5 --i-am-authorized

# Full active enumeration + AI prioritisation + HTML report:
py autopwn.py 10.10.10.5 --i-am-authorized --active --reason --html engagement.html
```

`autopwn` orchestrates real Kali tools (`nmap`, `whatweb`, `feroxbuster`/`gobuster`,
`nikto`, `enum4linux-ng`, `smbmap`, `searchsploit`, …); it detects which are installed
and skips the rest with an install hint. The methodology it follows lives in
`sentinel/methodology.py` — editing that file is how you teach it new techniques. Runs
are **authorization-gated** (`--i-am-authorized`) and scoped to the single IP you give
it; `--plan` previews everything without contacting the target.

## What makes it interesting

Most "privesc" tools (LinPEAS et al.) *dump* everything and leave the thinking to you.
Sentinel adds the thinking — and does it with a **dual brain**:

1. **A deterministic rule engine** (a curated GTFOBins/HackTricks knowledge base) that
   turns raw findings into ranked, ready-to-run attack vectors. **No API key, no
   internet, always works** — ideal on an exam clock.
2. **An optional LLM layer (Anthropic Claude)** that re-prioritises the vectors, spots
   escalations the rules miss by *combining* findings, and writes a short reasoning
   narrative — the judgment layer on top of the deterministic one.

The LLM is strictly optional and **degrades gracefully**: no `anthropic` package, no
API key, or a safety refusal → Sentinel silently falls back to the rule engine. **You
never need to pay for anything to use the core tool.**

## Architecture

```
 collect ─────────────► findings.json ─────────────► analyse
 (local / ssh)                                   (rule engine + optional LLM)

 sentinel/
 ├── findings.py     # Finding model + JSON (de)serialization
 ├── enumerator.py   # probe commands, PURE parsers, local/ssh/offline executors
 ├── knowledge.py    # GTFOBins-style KB: SUID / sudo / caps / groups / kernels
 ├── rule_engine.py  # findings -> ranked Vectors  (the free, deterministic brain)
 ├── llm_reasoner.py # optional Claude reasoning (structured JSON, graceful)
 ├── agent.py        # orchestrate enumerate -> reason -> (gated) execute
 └── report.py       # terminal output + self-contained HTML report
 sentinel.py         # CLI
 labs/sample_findings.json   # a synthetic multi-vector host for offline practice
 tests/test_units.py         # 18 offline tests (no host, no key)
```

## Techniques detected

SUID GTFOBins binaries, sudo-allowed GTFOBins binaries (with NOPASSWD weighting), full
sudo, `cap_setuid` file capabilities, writable `/etc/passwd` `/etc/shadow`
`/etc/sudoers`, writable cron paths, dangerous group membership (`docker`, `lxd`,
`disk`, `adm`, `shadow`), NFS `no_root_squash`, `sudo` `LD_PRELOAD` env_keep, and
advisory kernel-exploit hints (DirtyPipe, PwnKit, DirtyCow).

## Setup

The rule engine and offline analysis use **only the standard library** — nothing to
install. The extras are optional:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt   # paramiko (--ssh) + anthropic (--reason)
```

## Try it offline (no host, no key)

```powershell
py sentinel.py --offline labs\sample_findings.json
```

Sample output (ranked, each with the exact command):

```
--- #1  [#########.] 90  [rule] Member of 'docker' group ---
    why: Members of 'docker' can start containers that mount the host filesystem as root.
    $ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
--- #2  [#########.] 90  [rule] SUID find -> shell (GTFOBins) ---
    $ /usr/bin/find . -exec /bin/sh -p \; -quit
...
```

## Use against a real target

```powershell
# On a compromised Linux host:
py sentinel.py --local --save loot.json

# From your attacker box, over SSH:
py sentinel.py --ssh 10.10.10.50 -u bob -p bob --save loot.json

# Add the optional AI reasoning + an HTML report:
py sentinel.py --offline loot.json --reason --html report.html
```

Enabling the AI layer: set an Anthropic API key (`ANTHROPIC_API_KEY`) or run
`ant auth login`, then pass `--reason`. Without it, `--reason` prints a notice and uses
the rule engine.

## Executing payloads (guarded)

By default Sentinel **only suggests** — it never runs a payload. To actually run the
top vector's command you must pass **both** flags, and it still runs just one command
and reports the result (no blind looping):

```powershell
py sentinel.py --local --execute --i-am-authorized
```

## Tests

```powershell
py -m unittest discover -s tests -v
```

## Building a practice lab

See [`labs/vuln_lab.md`](labs/vuln_lab.md) for a script that plants classic
misconfigurations on a throwaway VM, plus pointers to TryHackMe / HackTheBox / VulnHub
targets.
