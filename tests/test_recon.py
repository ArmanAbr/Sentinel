"""
Offline tests for the recon/tool layer — no nmap, no target, no network.
Run:  py -m unittest discover -s tests
"""

import unittest

from sentinel import tools
from sentinel.methodology import playbook_for
from sentinel.recon import parse_nmap_xml, open_ports

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.6p1" extrainfo="Ubuntu"/>
        <script id="ssh-hostkey" output="2048 aa:bb ..."/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.29"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class TestNmapParser(unittest.TestCase):
    def setUp(self):
        self.services = parse_nmap_xml(SAMPLE_NMAP_XML)

    def test_only_open_ports_parsed(self):
        self.assertEqual(open_ports(self.services), [22, 80])  # 443 closed -> excluded

    def test_service_details(self):
        ssh = next(s for s in self.services if s.port == 22)
        self.assertEqual(ssh.name, "ssh")
        self.assertIn("OpenSSH", ssh.product)
        self.assertIn("7.6p1", ssh.banner)

    def test_scripts_captured(self):
        ssh = next(s for s in self.services if s.port == 22)
        self.assertIn("ssh-hostkey", ssh.scripts)

    def test_empty_and_garbage_input(self):
        self.assertEqual(parse_nmap_xml(""), [])
        self.assertEqual(parse_nmap_xml("not xml"), [])


class TestToolSafety(unittest.TestCase):
    def test_render_substitutes(self):
        argv = tools.render("nmap -sV -p{port} {ip}", {"ip": "10.10.10.5", "port": "22,80"})
        self.assertEqual(argv, ["nmap", "-sV", "-p22,80", "10.10.10.5"])

    def test_render_rejects_command_injection_in_ip(self):
        with self.assertRaises(ValueError):
            tools.render("nmap {ip}", {"ip": "10.10.10.5; rm -rf /"})

    def test_render_rejects_bad_scheme(self):
        with self.assertRaises(ValueError):
            tools.render("curl {scheme}://{ip}", {"ip": "10.10.10.5", "scheme": "file"})

    def test_valid_ip_or_host(self):
        self.assertTrue(tools.valid_ip_or_host("10.10.10.5"))
        self.assertTrue(tools.valid_ip_or_host("target.htb"))
        self.assertFalse(tools.valid_ip_or_host("10.0.0.1 && id"))


class TestPlaybook(unittest.TestCase):
    def test_http_playbook_by_name(self):
        steps = playbook_for("http", 80)
        self.assertTrue(any(s["tool"] == "feroxbuster" for s in steps))

    def test_smb_by_port_when_name_odd(self):
        steps = playbook_for("microsoft-ds", 445)
        self.assertTrue(any("smb" in s["tool"] or s["tool"] == "enum4linux-ng" for s in steps))

    def test_unknown_service_empty(self):
        self.assertEqual(playbook_for("weirdproto", 12345), [])


if __name__ == "__main__":
    unittest.main()
