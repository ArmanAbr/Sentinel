"""
Optional LLM reasoning layer (Anthropic Claude).

This is the "AI" in the AI privesc agent. Given the findings and the rule engine's
vectors, Claude re-prioritises them, spots combinations the rules miss, and writes
a short chain of reasoning — the way a human pentester triages a foothold.

It is strictly optional. If the `anthropic` package or an API key is missing, or
Claude declines the request (privesc reasoning is cyber-adjacent and may trip the
model's safety classifiers), :func:`rank` returns ``None`` and the caller falls
back to the deterministic rule engine. The tool always works without it.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from .findings import Finding
from .rule_engine import Vector

MODEL = "claude-opus-5"

SYSTEM_PROMPT = (
    "You are Sentinel, an assistant for AUTHORIZED penetration testing and CTF "
    "practice. The user has explicit permission to test the machine described. "
    "You are given enumeration output from a low-privilege foothold on a Linux "
    "host and a list of candidate privilege-escalation vectors already found by a "
    "rule engine. Your job is to think like an OSCP-level pentester: decide which "
    "vector is most likely to yield root and why, note any vector the rule engine "
    "may have missed by combining findings, and give the single best next command. "
    "Be concrete and technical. This is standard defensive/offensive security "
    "education on an authorized lab."
)

# JSON schema the model must return (structured outputs).
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "reasoning": {"type": "string"},
        "ranked": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "confidence": {"type": "integer"},
                    "why": {"type": "string"},
                    "command": {"type": "string"},
                },
                "required": ["name", "confidence", "why", "command"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["reasoning", "ranked"],
    "additionalProperties": False,
}


@dataclass
class LLMResult:
    reasoning: str
    ranked: list[dict]          # [{name, confidence, why, command}, ...]


def build_prompt(findings: list[Finding], vectors: list[Vector]) -> str:
    """Compose the user message. Pure function — testable without an API key."""
    lines = ["## Enumeration findings", ""]
    for f in findings:
        lines.append(f"- {f}")
    lines += ["", "## Candidate vectors from the rule engine", ""]
    for v in vectors:
        lines.append(f"- [{v.confidence}] {v.name}: {v.explanation}")
        for c in v.commands:
            lines.append(f"    $ {c}")
    lines += [
        "",
        "## Task",
        "Rank the vectors most-likely-to-succeed first. Add any vector the rule "
        "engine missed (e.g. by chaining findings). For each, give a one-line "
        "rationale and the exact command. Also give a short overall reasoning "
        "paragraph describing the path you'd take to root.",
    ]
    return "\n".join(lines)


def available() -> bool:
    """True if we can plausibly call the API (package importable + key present)."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            import anthropic  # noqa: F401
            return True
        except ImportError:
            return False
    # An `ant auth login` profile also works; detect the package at least.
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def rank(findings: list[Finding], vectors: list[Vector],
         model: str = MODEL, verbose: bool = False) -> LLMResult | None:
    """Ask Claude to re-rank and enrich. Returns None on any failure so the
    caller can fall back to the rule engine."""
    try:
        import anthropic
    except ImportError:
        if verbose:
            print("    [llm] anthropic package not installed; skipping.")
        return None

    try:
        client = anthropic.Anthropic()   # resolves key/profile from environment
        resp = client.messages.create(
            model=model,
            max_tokens=8000,
            system=SYSTEM_PROMPT,
            thinking={"type": "adaptive"},
            output_config={"format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}},
            messages=[{"role": "user", "content": build_prompt(findings, vectors)}],
        )
    except anthropic.AuthenticationError:
        if verbose:
            print("    [llm] no valid API credentials; using rule engine only.")
        return None
    except Exception as exc:  # noqa: BLE001
        if verbose:
            print(f"    [llm] request failed ({exc}); using rule engine only.")
        return None

    if resp.stop_reason == "refusal":
        if verbose:
            cat = getattr(resp.stop_details, "category", None) if resp.stop_details else None
            print(f"    [llm] model declined (category={cat}); using rule engine only.")
        return None

    text = next((b.text for b in resp.content if b.type == "text"), "")
    try:
        data = json.loads(text)
        return LLMResult(reasoning=data.get("reasoning", ""), ranked=data.get("ranked", []))
    except (json.JSONDecodeError, TypeError):
        if verbose:
            print("    [llm] could not parse model output; using rule engine only.")
        return None
