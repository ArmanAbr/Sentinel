"""
The Sentinel agent: orchestrates enumerate -> reason -> (optionally) execute.

Execution is OFF by default and gated behind an explicit authorization flag. In
suggest-only mode Sentinel never runs a payload — it only proposes them.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import report
from .findings import Finding
from .llm_reasoner import LLMResult, rank as llm_rank
from .rule_engine import Vector, detect


@dataclass
class Analysis:
    findings: list[Finding]
    vectors: list[Vector]
    llm: LLMResult | None = None


def analyze(findings: list[Finding], use_llm: bool = False, verbose: bool = False) -> Analysis:
    vectors = detect(findings)
    llm = None
    if use_llm:
        llm = llm_rank(findings, vectors, verbose=verbose)
        if llm:
            vectors = _merge_llm(vectors, llm)
    return Analysis(findings=findings, vectors=vectors, llm=llm)


def _merge_llm(vectors: list[Vector], llm: LLMResult) -> list[Vector]:
    """Fold the LLM's ranking/additions back into the vector list."""
    by_name = {v.name.lower(): v for v in vectors}
    merged: list[Vector] = []
    seen: set[str] = set()
    for r in llm.ranked:
        name = r.get("name", "")
        existing = by_name.get(name.lower())
        if existing:
            existing.confidence = int(r.get("confidence", existing.confidence))
            existing.source = "llm"
            merged.append(existing)
            seen.add(existing.name.lower())
        else:
            merged.append(Vector(
                name=name or "(AI suggestion)", technique="llm",
                confidence=int(r.get("confidence", 50)),
                evidence=["AI-inferred"], commands=[r.get("command", "")],
                explanation=r.get("why", ""), source="llm",
            ))
    # append any rule vectors the LLM didn't mention, lowest priority
    for v in vectors:
        if v.name.lower() not in seen and v not in merged:
            merged.append(v)
    merged.sort(key=lambda v: v.sort_key())
    return merged


def render(analysis: Analysis, limit: int = 20) -> None:
    report.print_findings_summary(analysis.findings)
    if analysis.llm:
        report.print_llm(analysis.llm)
    report.print_vectors(analysis.vectors, limit=limit)


def execute_top(analysis: Analysis, executor, dry_run: bool = True) -> None:
    """Attempt the top vector's first command via the executor.

    Guarded: does nothing unless the caller passes a real executor and dry_run
    is False. Even then it runs a single command and reports the result — it does
    not blindly loop, to avoid destructive surprises.
    """
    if not analysis.vectors:
        print("[-] Nothing to execute.")
        return
    top = analysis.vectors[0]
    cmd = top.commands[0].split("\n")[0]
    print(f"[*] Top vector: {top.name}")
    print(f"[*] Command:    {cmd}")
    if dry_run or executor is None:
        print("[i] Dry run — not executed. Re-run with --execute --i-am-authorized to run it.")
        return
    if cmd.lstrip().startswith("#"):
        print("[i] Top command is a manual step (comment), not auto-runnable. Do it by hand.")
        return
    print("[!] Executing...")
    out = executor(cmd)
    print(out)
    if "uid=0" in out or "root" in out.split("\n")[0:1]:
        print("[+] Looks like root! 🎉")
