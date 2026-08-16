"""
The autonomous engagement engine.

Given a target IP, `Engine` walks the methodology: recon -> per-service
enumeration -> vuln identification -> reporting. It is the deterministic brain
(works with no API key); the optional LLM layer (see `llm_reasoner`) can be layered
on to prioritise and suggest next actions.

`plan()` returns what the engine *would* run without executing anything — useful
for a dry run, for demos on a box without the tools, and as the checklist an
operator follows by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import tools
from .methodology import (
    HTTP_PORTS, RECON_STEPS, TLS_PORTS, WORDLISTS, playbook_for,
)
from .recon import Recon, Service


@dataclass
class StepResult:
    phase: str
    service: str
    tool: str
    command: str
    why: str
    output: str = ""
    ran: bool = False
    note: str = ""


@dataclass
class Engagement:
    ip: str
    services: list[Service] = field(default_factory=list)
    steps: list[StepResult] = field(default_factory=list)
    highlights: list[str] = field(default_factory=list)


# Interesting substrings to surface from raw tool output.
_INTEREST = [
    "anonymous", "220 ", "vsftpd", "no_root_squash", "STATUS_", "Sharename",
    "READ", "WRITE", "admin", "login", "upload", "wp-", "phpmyadmin", "/robots",
    "Set-Cookie", "X-Powered-By", "Server:", "CVE-", "default password",
    "IIS", "tomcat", "jenkins", "git", "backup", "Disallow",
]


def _http_meta(svc: Service) -> tuple[str, str]:
    scheme = "https" if svc.port in TLS_PORTS or "ssl" in svc.name or "https" in svc.name else "http"
    return scheme, WORDLISTS["dirs_small"]


class Engine:
    def __init__(self, ip: str, aggressiveness: str = "safe",
                 verbose: bool = False, domain: str = "") -> None:
        self.ip = ip
        self.aggressiveness = aggressiveness   # "safe" (read-only) or "active"
        self.verbose = verbose
        self.domain = domain or ip
        self.eng = Engagement(ip=ip)

    # -- planning (no execution) ----------------------------------------
    def plan(self, services: list[Service] | None = None) -> list[StepResult]:
        """Build the step list. If services are known, tailor to them; else show
        the generic recon + common-service plan."""
        steps: list[StepResult] = []
        for rs in RECON_STEPS:
            steps.append(StepResult("recon", "-", rs["tool"], rs["cmd"], rs["why"]))
        svcs = services if services is not None else _DEMO_SERVICES
        for svc in svcs:
            steps.extend(self._service_steps(svc, plan_only=True))
        steps.append(StepResult("identify", "-", "searchsploit",
                                "searchsploit <product> <version>",
                                "Map each service version to public exploits."))
        steps.append(StepResult("privesc", "-", "sentinel",
                                "py sentinel.py --ssh {ip} -u <user> -p <pass>",
                                "After a foothold, run the privesc engine to reach root."))
        return steps

    def _service_steps(self, svc: Service, plan_only: bool = False) -> list[StepResult]:
        steps = []
        pb = playbook_for(svc.name, svc.port)
        scheme, wl = _http_meta(svc)
        subs = {"ip": self.ip, "port": str(svc.port), "scheme": scheme,
                "domain": self.domain, "wordlist": wl,
                "url": f"{scheme}://{self.ip}:{svc.port}"}
        for step in pb:
            if self.aggressiveness == "safe" and step.get("kind") == "active":
                continue
            try:
                rendered = " ".join(tools.render(step["cmd"], subs))
            except ValueError:
                rendered = step["cmd"]
            steps.append(StepResult("enumerate", svc.name or str(svc.port),
                                    step["tool"], rendered, step["why"]))
        return steps

    # -- execution ------------------------------------------------------
    def run(self) -> Engagement:
        print(f"[*] Phase 1/5 — recon on {self.ip}")
        self.eng.services = Recon(self.ip, verbose=self.verbose).run()
        for s in self.eng.services:
            print(f"    {s}")

        print(f"[*] Phase 2/5 — service enumeration ({self.aggressiveness})")
        for svc in self.eng.services:
            planned = self._service_steps(svc)
            if planned:
                print(f"  [{svc.port}/{svc.name}]")
            for sr in planned:
                subs = self._subs_for(svc)
                res = tools.run(_template_from_rendered(sr.command), subs,
                                timeout=180, verbose=self.verbose)
                sr.ran = res.ok and res.returncode != 127
                sr.output = res.output[:8000]
                sr.note = res.error
                if not sr.ran and res.error:
                    print(f"    [-] {sr.tool}: {res.error}")
                else:
                    self._harvest(sr)
                self.eng.steps.append(sr)

        print(f"[*] Phase 3/5 — vuln identification")
        self._identify()

        print(f"[*] Phase 4/5 — privesc: run after you get a foothold (see report)")
        print(f"[*] Phase 5/5 — loot: grep for flags once you have a shell")
        return self.eng

    def _subs_for(self, svc: Service) -> dict:
        scheme, wl = _http_meta(svc)
        return {"ip": self.ip, "port": str(svc.port), "scheme": scheme,
                "domain": self.domain, "wordlist": wl,
                "url": f"{scheme}://{self.ip}:{svc.port}"}

    def _harvest(self, sr: StepResult) -> None:
        for line in sr.output.splitlines():
            low = line.lower()
            if any(tok.lower() in low for tok in _INTEREST):
                h = f"[{sr.service}] {line.strip()[:160]}"
                if h not in self.eng.highlights:
                    self.eng.highlights.append(h)

    def _identify(self) -> None:
        if not tools.available("searchsploit"):
            self.eng.steps.append(StepResult(
                "identify", "-", "searchsploit", "searchsploit <product> <version>",
                "searchsploit not installed (apt install exploitdb). Search versions manually.",
                note="missing"))
            return
        seen = set()
        for svc in self.eng.services:
            term = (svc.product or svc.name).split()[0] if (svc.product or svc.name) else ""
            if not term or term in seen:
                continue
            seen.add(term)
            argv = ["searchsploit"] + [t for t in (term, svc.version) if t]
            out = _run_argv(argv)
            self.eng.steps.append(StepResult(
                "identify", svc.name, "searchsploit", " ".join(argv),
                f"Public exploits for {term} {svc.version}".strip(),
                output=out[:4000], ran=True))


def _template_from_rendered(cmd: str) -> str:
    # The command was already rendered (safe values substituted); re-run as-is by
    # tokenising. We wrap it back through tools.run via a trivial template with no
    # placeholders, so validation is a no-op and execution stays argv-based.
    return cmd


def _run_argv(argv: list[str]) -> str:
    import subprocess
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        return p.stdout + p.stderr
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"


# Common services used only for the generic --plan preview (no target contacted).
_DEMO_SERVICES = [
    Service(port=21, name="ftp", product="vsftpd", version="3.0.3"),
    Service(port=22, name="ssh", product="OpenSSH", version="7.6p1"),
    Service(port=80, name="http", product="Apache httpd", version="2.4.29"),
    Service(port=445, name="microsoft-ds", product="Samba"),
]
