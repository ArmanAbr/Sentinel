"""
Sentinel — an autonomous privilege-escalation agent.

Sentinel enumerates a compromised Linux host, *reasons* about the findings like a
pentester (deterministically via a rule engine, and optionally with an LLM), and
proposes — or, when authorized, executes — the exact next step toward root.

FOR AUTHORIZED USE ONLY: your own labs, CTF machines, and engagements where you
have explicit written permission. See README.md.
"""

__version__ = "1.0.0"
