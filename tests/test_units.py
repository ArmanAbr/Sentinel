"""
Offline tests — no network, no API key, no target host.
Run:  py -m unittest discover -s tests
"""

import os
import unittest

from sentinel import enumerator as en
from sentinel import knowledge as kb
from sentinel.findings import Finding, load
from sentinel.llm_reasoner import build_prompt
from sentinel.rule_engine import detect

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "labs", "sample_findings.json")


class TestParsers(unittest.TestCase):
    def test_parse_suid(self):
        out = en.parse_suid("/usr/bin/find\n/usr/bin/passwd\nnot-a-path\n")
        self.assertEqual([f.value for f in out], ["/usr/bin/find", "/usr/bin/passwd"])

    def test_parse_sudo_nopasswd(self):
        out = en.parse_sudo("    (root) NOPASSWD: /usr/bin/find")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].detail, "NOPASSWD")

    def test_parse_caps(self):
        out = en.parse_caps("/usr/bin/python3.8 cap_setuid=ep")
        self.assertEqual(out[0].value, "/usr/bin/python3.8")
        self.assertIn("cap_setuid", out[0].detail)

    def test_parse_kernel(self):
        out = en.parse_kernel("Linux h 5.4.0-42-generic #46 x86_64\n---\nPRETTY_NAME=\"Ubuntu 20.04\"")
        kernels = [f for f in out if f.key == "kernel"]
        self.assertEqual(kernels[0].value, "5.4.0-42-generic")

    def test_parse_groups_filters(self):
        out = en.parse_groups("bob docker adm musicfans")
        self.assertEqual(sorted(f.value for f in out), ["adm", "docker"])

    def test_parse_nfs_only_no_root_squash(self):
        text = "/a *(rw,root_squash)\n/b *(rw,no_root_squash)\n"
        out = en.parse_nfs(text)
        self.assertEqual([f.value.split()[0] for f in out], ["/b"])

    def test_parse_path_flags_relative_and_writable(self):
        # "." and empty (CWD), any relative entry, and /tmp|/home are unsafe;
        # normal absolute dirs are not.
        out = en.parse_path("/usr/bin:bin:.::/tmp/x:/home/bob/.local/bin:/sbin")
        flagged = [f.value for f in out]
        self.assertEqual(flagged, ["bin", ".", ".", "/tmp/x", "/home/bob/.local/bin"])

    def test_parse_path_clean_path_has_no_findings(self):
        self.assertEqual(en.parse_path("/usr/local/bin:/usr/bin:/bin:/sbin"), [])


class TestKnowledge(unittest.TestCase):
    def test_suid_payload_formats(self):
        cmd = kb.SUID_PAYLOADS["find"].format(bin="/usr/bin/find")
        self.assertIn("/usr/bin/find", cmd)
        self.assertIn("-exec", cmd)

    def test_kernel_hint_dirtycow(self):
        # 3.13 should match DirtyCow (< 4.8.3)
        self.assertTrue(kb._ver_less("3.13.0-24-generic", (4, 8, 3)))
        self.assertFalse(kb._ver_less("5.4.0", (4, 8, 3)))

    def test_dirtypipe_vulnerable_versions(self):
        # In range and below the series fix -> vulnerable.
        for v in ("5.8.0", "5.10.0-40-generic", "5.15.24", "5.16.10", "5.12.5"):
            self.assertTrue(kb._dirtypipe_vulnerable(v), v)

    def test_dirtypipe_patched_versions(self):
        # Backport fixes and anything at/above them in-series -> patched.
        for v in ("5.16.11", "5.15.25", "5.15.30", "5.10.102", "5.10.150"):
            self.assertFalse(kb._dirtypipe_vulnerable(v), v)

    def test_dirtypipe_out_of_range(self):
        # Introduced in 5.8; gone by 5.17.
        self.assertFalse(kb._dirtypipe_vulnerable("5.4.0-42-generic"))
        self.assertFalse(kb._dirtypipe_vulnerable("5.17.0"))

    def test_basename(self):
        self.assertEqual(kb.basename("/usr/bin/vim.basic"), "vim.basic")


class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        self.findings, _ = load(SAMPLE)
        self.vectors = detect(self.findings)

    def test_finds_multiple_vectors(self):
        self.assertGreaterEqual(len(self.vectors), 6)

    def test_sudo_nopasswd_find_is_high_and_first(self):
        names = [v.name for v in self.vectors]
        self.assertTrue(any("sudo find" in n for n in names))
        # highest-confidence vector should be a HIGH one
        self.assertGreaterEqual(self.vectors[0].confidence, 90)

    def test_suid_find_detected_with_gtfobins_cmd(self):
        v = next(v for v in self.vectors if v.name.startswith("SUID find"))
        self.assertIn("-exec /bin/sh -p", v.commands[0])

    def test_cap_setuid_python_detected(self):
        self.assertTrue(any("cap_setuid" in v.name for v in self.vectors))

    def test_writable_passwd_detected(self):
        self.assertTrue(any("Writable /etc/passwd" == v.name for v in self.vectors))

    def test_docker_group_detected(self):
        v = next(v for v in self.vectors if "docker" in v.name)
        self.assertIn("chroot /mnt", v.commands[0])

    def test_boring_suid_passwd_not_flagged_as_unusual(self):
        self.assertFalse(any("passwd" in v.name and "Unusual" in v.name for v in self.vectors))

    def test_custom_suid_flagged_unusual(self):
        self.assertTrue(any("custombackup" in v.name for v in self.vectors))


class TestLLMPromptBuilder(unittest.TestCase):
    def test_prompt_contains_findings_and_vectors(self):
        findings, _ = load(SAMPLE)
        vectors = detect(findings)
        prompt = build_prompt(findings, vectors)
        self.assertIn("Enumeration findings", prompt)
        self.assertIn("/usr/bin/find", prompt)
        self.assertIn("Candidate vectors", prompt)


if __name__ == "__main__":
    unittest.main()
