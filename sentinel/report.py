"""
Presentation: pretty terminal output and an optional self-contained HTML report.
"""

from __future__ import annotations

import html

from .findings import Finding
from .llm_reasoner import LLMResult
from .rule_engine import Vector


def _bar(conf: int) -> str:
    filled = round(conf / 10)
    return "[" + "#" * filled + "." * (10 - filled) + f"] {conf}"


def print_findings_summary(findings: list[Finding]) -> None:
    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(by_cat.items()))
    print(f"[*] Collected {len(findings)} findings ({summary})\n")


def print_vectors(vectors: list[Vector], limit: int = 20) -> None:
    if not vectors:
        print("[-] No known privilege-escalation vectors detected by the rule engine.")
        return
    print(f"[+] {len(vectors)} escalation vector(s), most promising first:\n")
    for i, v in enumerate(vectors[:limit], 1):
        tag = "AI" if v.source == "llm" else "rule"
        print(f"--- #{i}  {_bar(v.confidence)}  [{tag}] {v.name} ---")
        print(f"    why: {v.explanation}")
        for c in v.commands:
            for ln in c.split("\n"):
                print(f"    $ {ln}")
        if v.reference:
            print(f"    ref: {v.reference}")
        print()


def print_llm(result: LLMResult) -> None:
    print("=" * 68)
    print("[AI] Claude's reasoning:\n")
    print("    " + result.reasoning.replace("\n", "\n    "))
    print()
    if result.ranked:
        print("[AI] Recommended order:\n")
        for i, r in enumerate(result.ranked, 1):
            print(f"    {i}. ({r.get('confidence','?')}) {r.get('name','?')}")
            print(f"       {r.get('why','')}")
            print(f"       $ {r.get('command','')}")
        print()
    print("=" * 68 + "\n")


def print_plan(steps) -> None:
    """Render the engagement plan (StepResult list) grouped by phase."""
    phase = None
    for s in steps:
        if s.phase != phase:
            phase = s.phase
            print(f"\n=== phase: {phase} ===")
        target = f"{s.service}" if s.service not in ("-", "") else ""
        head = f"  [{s.tool}] {target}".rstrip()
        print(head)
        print(f"      $ {s.command}")
        print(f"      why: {s.why}")


def print_engagement(eng) -> None:
    print("\n" + "=" * 68)
    print(f"[*] Engagement summary for {eng.ip}")
    print("=" * 68)
    print(f"\n[+] Services ({len(eng.services)}):")
    for s in eng.services:
        print(f"    {s}")
    if eng.highlights:
        print(f"\n[+] Highlights ({len(eng.highlights)}):")
        for h in eng.highlights[:40]:
            print(f"    * {h}")
    ran = [s for s in eng.steps if s.ran]
    print(f"\n[+] Ran {len(ran)}/{len(eng.steps)} enumeration steps.")
    print("\n[i] Next: pick a foothold from the highlights/exploits above, get a "
          "shell, then run:\n    py sentinel.py --ssh %s -u <user> -p <pass> --reason" % eng.ip)


def export_engagement_html(path: str, eng) -> None:
    def esc(s: str) -> str:
        return html.escape(str(s))

    svc_rows = "".join(
        f"<tr><td>{s.port}/{s.proto}</td><td>{esc(s.name)}</td><td>{esc(s.banner)}</td></tr>"
        for s in eng.services
    )
    hi = "".join(f"<li>{esc(h)}</li>" for h in eng.highlights)
    step_rows = "".join(
        f"<tr><td>{esc(s.phase)}</td><td>{esc(s.service)}</td><td><code>{esc(s.command)}</code></td>"
        f"<td>{'ran' if s.ran else esc(s.note or 'skipped')}</td></tr>"
        for s in eng.steps
    )
    doc = f"""<!doctype html><meta charset="utf-8">
<title>Sentinel engagement — {esc(eng.ip)}</title>
<style>
 body{{font:15px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem}}
 h1{{border-bottom:2px solid #b00}} table{{border-collapse:collapse;width:100%;margin:1rem 0}}
 td,th{{border:1px solid #ccc;padding:6px;text-align:left;vertical-align:top}}
 code{{background:#f4f4f4;padding:1px 3px}} .warn{{color:#b00}}
</style>
<h1>Sentinel engagement report</h1>
<p class="warn">Authorized testing only. Target: <b>{esc(eng.ip)}</b></p>
<h2>Services</h2><table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>{svc_rows}</table>
<h2>Highlights</h2><ul>{hi}</ul>
<h2>Steps</h2><table><tr><th>Phase</th><th>Service</th><th>Command</th><th>Status</th></tr>{step_rows}</table>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    print(f"[+] Engagement report written to {path}")


def export_html(path: str, findings: list[Finding], vectors: list[Vector],
                llm: LLMResult | None, target: str) -> None:
    def esc(s: str) -> str:
        return html.escape(str(s))

    rows = []
    for i, v in enumerate(vectors, 1):
        cmds = "<br>".join(esc(ln) for c in v.commands for ln in c.split("\n"))
        rows.append(
            f"<tr><td>{i}</td><td>{v.confidence}</td><td>{esc(v.name)}</td>"
            f"<td>{esc(v.explanation)}</td><td><code>{cmds}</code></td></tr>"
        )
    llm_html = ""
    if llm:
        llm_html = f"<h2>AI reasoning</h2><pre>{esc(llm.reasoning)}</pre>"

    doc = f"""<!doctype html><meta charset="utf-8">
<title>Sentinel report — {esc(target)}</title>
<style>
 body{{font:15px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#111}}
 h1{{border-bottom:2px solid #b00}} table{{border-collapse:collapse;width:100%}}
 td,th{{border:1px solid #ccc;padding:6px;vertical-align:top;text-align:left}}
 code{{background:#f4f4f4;padding:1px 3px}} .warn{{color:#b00}}
</style>
<h1>Sentinel privilege-escalation report</h1>
<p class="warn">Authorized testing only. Target: <b>{esc(target)}</b> — {len(findings)} findings, {len(vectors)} vectors.</p>
{llm_html}
<h2>Escalation vectors</h2>
<table><tr><th>#</th><th>Conf</th><th>Vector</th><th>Why</th><th>Commands</th></tr>
{''.join(rows)}
</table>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    print(f"[+] HTML report written to {path}")
