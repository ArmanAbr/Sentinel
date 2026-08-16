#!/usr/bin/env python3
"""
Sentinel autopwn — autonomous Linux engagement engine.

Give it a target IP and it walks the full methodology: recon (nmap) -> per-service
enumeration -> vuln identification -> a prioritized report telling you exactly how
to get a foothold, then hand off to the privesc engine (sentinel.py) for root.

              ⚠  AUTHORIZED TARGETS ONLY  ⚠
Only run this against machines you own or are explicitly permitted to test
(HackTheBox, TryHackMe, your own labs, in-scope engagements).

Examples
--------
  # See the full attack plan WITHOUT touching the target (works with no tools):
  py autopwn.py 10.10.10.5 --plan

  # Run recon + safe (read-only) enumeration:
  py autopwn.py 10.10.10.5 --i-am-authorized

  # Include active enumeration (dir brute, nikto, vhost) + HTML report:
  py autopwn.py 10.10.10.5 --i-am-authorized --active --html engagement.html

  # Layer Claude's prioritisation on top (needs an Anthropic API key):
  py autopwn.py 10.10.10.5 --i-am-authorized --active --reason
"""

from __future__ import annotations

import argparse
import sys

from sentinel import report, tools
from sentinel.engine import Engine
from sentinel.llm_reasoner import available as llm_available

BANNER = r"""
   ___       __       ___
  / _ |__ __/ /____  / _ \_    _____  ___
 / __ / // / __/ _ \/ ___/ |/|/ / _ \/ _ \
/_/ |_\_,_/\__/\___/_/   |__,__/_//_/_//_/
   Sentinel autonomous engagement engine
"""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Autonomous Linux recon + enumeration engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__,
    )
    p.add_argument("ip", help="target IP or hostname (must be authorized)")
    p.add_argument("--plan", action="store_true",
                   help="print the attack plan without executing anything")
    p.add_argument("--active", action="store_true",
                   help="include noisy active enumeration (dir brute, nikto, vhost)")
    p.add_argument("--domain", help="virtual-host domain (for vhost enum), e.g. box.htb")
    p.add_argument("--reason", action="store_true", help="use the optional Claude AI layer")
    p.add_argument("--html", metavar="FILE", help="write an HTML engagement report")
    p.add_argument("-v", "--verbose", action="store_true", help="show each command as it runs")
    p.add_argument("--i-am-authorized", action="store_true",
                   help="required acknowledgement to actually scan the target")

    args = p.parse_args(argv)
    print(BANNER)

    if not tools.valid_ip_or_host(args.ip):
        print(f"[!] {args.ip!r} is not a valid IP/hostname.")
        return 2

    aggressiveness = "active" if args.active else "safe"
    engine = Engine(args.ip, aggressiveness=aggressiveness,
                    verbose=args.verbose, domain=args.domain or "")

    # --- plan mode: no execution --------------------------------------
    if args.plan:
        print(f"[*] Attack plan for {args.ip}  (aggressiveness: {aggressiveness})")
        print("[i] Nothing is executed in --plan mode. This is the methodology "
              "Sentinel will follow once you authorize a live run.")
        report.print_plan(engine.plan())
        return 0

    # --- live run: gated ----------------------------------------------
    if not args.i_am_authorized:
        print("[!] Refusing to scan a target without --i-am-authorized.")
        print("    Use --plan to preview the methodology safely, or add "
              "--i-am-authorized once you have permission.")
        return 2

    if args.reason and not llm_available():
        print("[i] --reason requested but no Anthropic SDK/API key found; "
              "running the deterministic engine only.\n")

    eng = engine.run()
    report.print_engagement(eng)

    if args.reason and llm_available():
        _ai_prioritise(eng, args.verbose)

    if args.html:
        report.export_engagement_html(args.html, eng)

    return 0


def _ai_prioritise(eng, verbose: bool) -> None:
    """Optional: ask Claude to read the engagement and suggest the next move."""
    try:
        import anthropic
    except ImportError:
        return
    from sentinel.methodology import summary_for_llm
    services = "\n".join(f"- {s}" for s in eng.services)
    highlights = "\n".join(f"- {h}" for h in eng.highlights[:60])
    prompt = (
        f"{summary_for_llm()}\n\nTarget {eng.ip} enumeration results:\n"
        f"## Services\n{services}\n\n## Interesting findings\n{highlights}\n\n"
        "As an OSCP-level pentester on an AUTHORIZED lab box, give the 3 most "
        "promising footholds in priority order, each with the exact next command "
        "to try, and note any exploit/CVE or default-cred angle you'd chase first."
    )
    try:
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model="claude-opus-5", max_tokens=4000,
            thinking={"type": "adaptive"},
            system="You assist with authorized penetration testing and CTF practice.",
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as exc:  # noqa: BLE001
        if verbose:
            print(f"    [llm] {exc}")
        return
    if resp.stop_reason == "refusal":
        print("    [llm] model declined; using deterministic report only.")
        return
    text = next((b.text for b in resp.content if b.type == "text"), "")
    print("\n" + "=" * 68 + "\n[AI] Claude's recommended plan of attack:\n")
    print("    " + text.replace("\n", "\n    "))
    print("=" * 68)


if __name__ == "__main__":
    sys.exit(main())
