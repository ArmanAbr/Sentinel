"""
Recon phase: nmap-driven port and service discovery.

`parse_nmap_xml` is pure (XML text in, Service objects out) so it is unit-testable
without nmap or a target. `Recon.run` chains the RECON_STEPS: a fast full-port
sweep, then a service/version scan on whatever was found.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from . import tools
from .methodology import RECON_STEPS


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extra: str = ""
    scripts: dict = field(default_factory=dict)

    @property
    def banner(self) -> str:
        bits = [b for b in (self.product, self.version, self.extra) if b]
        return " ".join(bits)

    def __str__(self) -> str:
        return f"{self.port}/{self.proto} {self.state} {self.name} {self.banner}".strip()


def parse_nmap_xml(xml_text: str) -> list[Service]:
    """Parse `nmap -oX -` output into Service objects."""
    services: list[Service] = []
    if not xml_text.strip():
        return services
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return services
    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"
            if state not in ("open", "open|filtered"):
                continue
            svc_el = port.find("service")
            svc = Service(
                port=int(port.get("portid")),
                proto=port.get("protocol", "tcp"),
                state=state,
                name=(svc_el.get("name") if svc_el is not None else "") or "",
                product=(svc_el.get("product") if svc_el is not None else "") or "",
                version=(svc_el.get("version") if svc_el is not None else "") or "",
                extra=(svc_el.get("extrainfo") if svc_el is not None else "") or "",
            )
            for script in port.findall("script"):
                svc.scripts[script.get("id", "?")] = script.get("output", "")
            services.append(svc)
    return services


def open_ports(services: list[Service]) -> list[int]:
    return sorted({s.port for s in services})


class Recon:
    def __init__(self, ip: str, verbose: bool = False, quick: bool = False) -> None:
        self.ip = ip
        self.verbose = verbose
        self.quick = quick    # quick = skip full -p- sweep, use top ports

    def run(self) -> list[Service]:
        if not tools.available("nmap"):
            print("[!] nmap not found — install it (apt install nmap) to run recon.")
            return []

        # Step 1: find open ports.
        if self.quick:
            r = tools.run("nmap -F -Pn -oX - {ip}", {"ip": self.ip},
                          timeout=300, verbose=self.verbose)
        else:
            step = RECON_STEPS[0]
            r = tools.run(step["cmd"], {"ip": self.ip}, timeout=900, verbose=self.verbose)
        found = parse_nmap_xml(r.stdout)
        ports = open_ports(found)
        if not ports:
            print("[-] No open TCP ports found.")
            return []
        print(f"[+] Open ports: {', '.join(map(str, ports))}")

        # Step 2: service/version + default scripts on the open ports.
        svc_step = RECON_STEPS[1]
        r2 = tools.run(svc_step["cmd"], {"ip": self.ip, "port": ",".join(map(str, ports))},
                       timeout=900, verbose=self.verbose)
        services = parse_nmap_xml(r2.stdout)
        # Fall back to step-1 data if the service scan returned nothing parseable.
        return services or found
