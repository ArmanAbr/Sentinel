#!/usr/bin/env python3
"""
Sentinel — an autonomous privilege-escalation agent.

AUTHORIZED USE ONLY. Run only against systems you own or have explicit written
permission to test (your labs, CTF machines, in-scope engagements).

Sources (pick one):
  --offline FILE     analyse a saved findings.json (no target needed)
  --local            enumerate the machine Sentinel is running on
  --ssh HOST         enumerate a target over SSH (-u user, -p pass or -k key)

Examples
--------
  # Analyse the bundled sample lab, deterministic engine only (no API key):
  py sentinel.py --offline labs/sample_findings.json

  # Enumerate over SSH, collect to JSON, and reason:
  py sentinel.py --ssh 10.10.10.5 -u bob -p hunter2 --save loot.json

  # Add the optional AI layer (needs an Anthropic API key) + HTML report:
  py sentinel.py --offline labs/sample_findings.json --reason --html report.html

  # Actually run the top payload (guarded):
  py sentinel.py --local --execute --i-am-authorized
"""

from __future__ import annotations

import argparse
import sys

from sentinel import agent, report
from sentinel.enumerator import Enumerator, local_executor, ssh_executor
from sentinel.findings import dump, load
from sentinel.llm_reasoner import available as llm_available

BANNER = r"""
  ___  ___ _  _ _____ ___ _  _ ___ _
 / __|| __| \| |_   _|_ _| \| | __| |
 \__ \| _|| .` | | |  | || .` | _|| |__
 |___/|___|_|\_| |_| |___|_|\_|___|____|
   autonomous privilege-escalation agent
"""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Enumerate a Linux host, reason about privesc, propose/execute the next step.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--offline", metavar="FILE", help="analyse a saved findings.json")
    src.add_argument("--local", action="store_true", help="enumerate the local machine")
    src.add_argument("--ssh", metavar="HOST", help="enumerate a target over SSH")

    p.add_argument("-u", "--user", help="SSH username")
    p.add_argument("-p", "--password", help="SSH password")
    p.add_argument("-k", "--key", help="SSH private key file")
    p.add_argument("--port", type=int, default=22, help="SSH port (default 22)")

    p.add_argument("--reason", action="store_true", help="use the optional Claude AI layer")
    p.add_argument("--model", default="claude-opus-5", help="Anthropic model for --reason")
    p.add_argument("--save", metavar="FILE", help="save collected findings to JSON")
    p.add_argument("--html", metavar="FILE", help="write an HTML report")
    p.add_argument("--limit", type=int, default=20, help="max vectors to show")
    p.add_argument("-v", "--verbose", action="store_true", help="show probes / diagnostics")

    p.add_argument("--execute", action="store_true", help="run the top payload (guarded)")
    p.add_argument("--i-am-authorized", action="store_true",
                   help="required acknowledgement to actually execute payloads")

    args = p.parse_args(argv)
    print(BANNER)

    # --- collect findings ----------------------------------------------
    target = "offline"
    ssh_close = None
    if args.offline:
        findings, meta = load(args.offline)
        target = meta.get("target", args.offline)
        print(f"[*] Loaded {len(findings)} findings from {args.offline}")
    elif args.local:
        target = "localhost"
        print("[*] Enumerating local machine ...")
        findings = Enumerator(local_executor, verbose=args.verbose).run()
    else:  # ssh
        if not args.user:
            print("[!] --ssh requires -u/--user (and -p/--password or -k/--key).")
            return 2
        target = args.ssh
        print(f"[*] Enumerating {args.user}@{args.ssh} over SSH ...")
        try:
            execu = ssh_executor(args.ssh, args.user, args.password or "", args.key or "", args.port)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] SSH connection failed: {exc}")
            return 2
        ssh_close = getattr(execu, "close", None)
        findings = Enumerator(execu, verbose=args.verbose).run()

    if args.save:
        dump(findings, args.save, meta={"target": target})
        print(f"[+] Saved findings to {args.save}")

    if not findings:
        print("[-] No findings collected — nothing to analyse.")
        if ssh_close:
            ssh_close()
        return 1

    # --- reason ---------------------------------------------------------
    if args.reason and not llm_available():
        print("[i] --reason requested but no Anthropic SDK/API key found. "
              "Falling back to the rule engine (still fully functional).\n")
    use_llm = args.reason and llm_available()

    analysis = agent.analyze(findings, use_llm=use_llm, verbose=args.verbose)
    print()
    agent.render(analysis, limit=args.limit)

    if args.html:
        report.export_html(args.html, analysis.findings, analysis.vectors,
                           analysis.llm, target)

    # --- execute (guarded) ---------------------------------------------
    if args.execute:
        if not args.i_am_authorized:
            print("[!] Refusing to execute without --i-am-authorized. "
                  "Only run payloads on systems you are authorized to test.")
        else:
            execu = local_executor if args.local else (execu if args.ssh else None)
            agent.execute_top(analysis, execu, dry_run=False)

    if ssh_close:
        ssh_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
