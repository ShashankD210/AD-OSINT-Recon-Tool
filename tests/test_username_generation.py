#!/usr/bin/env python3
"""
Unit tests for ad_osint_recon.py
Run with: python3 -m pytest tests/test_username_generation.py -v
Or:       python3 tests/test_username_generation.py
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ad_osint_recon import (
    NameParts,
    generate_usernames,
    build_username_report,
    build_search_dorks,
    _clean_name_part,
    MAX_SAM_ACCOUNT_LEN,
    NICKNAME_MAP,
    parse_target,
    is_ip_address,
    escape_html,
    render_html_report,
    build_environment_report,
)


class TestCleanNamePart(unittest.TestCase):
    def test_basic_lowercase(self):
        self.assertEqual(_clean_name_part("Jane"), "jane")

    def test_strips_punctuation(self):
        self.assertEqual(_clean_name_part("O'Brien"), "obrien")
        self.assertEqual(_clean_name_part("Mary-Anne"), "maryanne")

    def test_strips_numbers(self):
        self.assertEqual(_clean_name_part("User123"), "user")

    def test_handles_whitespace(self):
        self.assertEqual(_clean_name_part("  John  "), "john")


class TestNamePartsParse(unittest.TestCase):
    def test_two_token_name(self):
        parts = NameParts.parse("Jane Smith")
        self.assertEqual(parts.first, "jane")
        self.assertEqual(parts.last, "smith")
        self.assertEqual(parts.middle, "")
        self.assertEqual(parts.last2, "")

    def test_three_token_name_middle_initial(self):
        parts = NameParts.parse("John A. Doe")
        self.assertEqual(parts.first, "john")
        self.assertEqual(parts.last, "doe")
        self.assertEqual(parts.middle, "a")
        self.assertEqual(parts.last2, "a")

    def test_hyphenated_first_name(self):
        parts = NameParts.parse("Mary-Anne O'Brien")
        self.assertEqual(parts.first, "mary")
        self.assertEqual(parts.last, "obrien")
        self.assertEqual(parts.middle, "anne")
        self.assertEqual(parts.last2, "anne")

    def test_spanish_double_surname(self):
        parts = NameParts.parse("Maria Garcia Lopez")
        self.assertEqual(parts.first, "maria")
        self.assertEqual(parts.last, "lopez")
        self.assertEqual(parts.middle, "garcia")
        self.assertEqual(parts.last2, "garcia")

    def test_single_token_name(self):
        parts = NameParts.parse("Cher")
        self.assertEqual(parts.first, "cher")
        self.assertEqual(parts.last, "")

    def test_extra_whitespace(self):
        parts = NameParts.parse("  John   A.   Doe  ")
        self.assertEqual(parts.first, "john")
        self.assertEqual(parts.last, "doe")

    def test_empty_name_raises(self):
        with self.assertRaises(ValueError):
            NameParts.parse("")

    def test_empty_whitespace_raises(self):
        with self.assertRaises(ValueError):
            NameParts.parse("   ")


class TestNameVariants(unittest.TestCase):
    def test_no_nickname(self):
        parts = NameParts.parse("Jane Smith")
        self.assertEqual(parts.name_variants(), ["jane"])

    def test_nickname_to_formal(self):
        parts = NameParts.parse("Bob Smith")
        variants = parts.name_variants()
        self.assertIn("bob", variants)
        self.assertIn("robert", variants)

    def test_formal_to_nickname(self):
        parts = NameParts.parse("Robert Smith")
        variants = parts.name_variants()
        self.assertIn("robert", variants)
        self.assertIn("bob", variants)


class TestGenerateUsernames(unittest.TestCase):
    def test_basic_patterns(self):
        parts = NameParts.parse("Jane Smith")
        result = generate_usernames(parts)
        expected_substrings = [
            "jane.smith",
            "janesmith",
            "jsmith",
            "janes",
            "smithj",
            "smith.jane",
            "smithjane",
            "j.smith",
            "jane_smith",
            "smith_jane",
        ]
        for pattern in expected_substrings:
            self.assertIn(pattern, result, f"Missing pattern: {pattern}")

    def test_sam_account_length_limit(self):
        parts = NameParts.parse("Jane Smith")
        result = generate_usernames(parts)
        for uname in result:
            self.assertLessEqual(
                len(uname),
                MAX_SAM_ACCOUNT_LEN,
                f"Username '{uname}' exceeds {MAX_SAM_ACCOUNT_LEN} chars",
            )

    def test_empty_result_for_empty_first_and_last(self):
        parts = NameParts(first="", last="")
        result = generate_usernames(parts)
        self.assertEqual(result, set())

    def test_double_surname_patterns(self):
        parts = NameParts.parse("Maria Garcia Lopez")
        result = generate_usernames(parts)
        self.assertIn("maria.garcialopez", result)
        self.assertIn("maria.garcia.lopez", result)
        self.assertIn("mgarcialopez", result)
        self.assertIn("maria.garcia", result)

    def test_middle_initial_patterns(self):
        parts = NameParts.parse("John A. Doe")
        result = generate_usernames(parts)
        self.assertIn("john.a.doe", result)
        self.assertIn("jadoe", result)

    def test_nickname_expansion(self):
        parts = NameParts.parse("Bob Smith")
        result = generate_usernames(parts)
        self.assertIn("bob.smith", result)
        self.assertIn("robert.smith", result)
        self.assertIn("bsmith", result)
        self.assertIn("rsmith", result)

    def test_name_without_last(self):
        parts = NameParts.parse("Cher")
        result = generate_usernames(parts)
        self.assertIn("cher", result)


class TestBuildUsernameReport(unittest.TestCase):
    def test_report_structure(self):
        names = ["Jane Smith", "John Doe"]
        rows = build_username_report(names, "victim.com")
        self.assertGreater(len(rows), 0)
        for row in rows:
            self.assertIn("full_name", row)
            self.assertIn("candidate_username", row)
            self.assertIn("candidate_email", row)
            self.assertTrue(row["candidate_email"].endswith("@victim.com"))

    def test_report_without_domain(self):
        names = ["Jane Smith"]
        rows = build_username_report(names, "")
        for row in rows:
            self.assertNotIn("candidate_email", row)


class TestBuildSearchDorks(unittest.TestCase):
    def test_dork_generation_with_domain(self):
        dorks = build_search_dorks("victim.com", "VictimCorp")
        self.assertGreater(len(dorks), 0)
        for dork in dorks:
            self.assertIsInstance(dork, str)
            self.assertTrue(len(dork) > 0)

    def test_dork_generation_without_company_name(self):
        dorks = build_search_dorks("victim.com")
        self.assertGreater(len(dorks), 0)

    def test_dorks_contain_expected_patterns(self):
        dorks = build_search_dorks("victim.com", "VictimCorp")
        joined = " ".join(dorks)
        self.assertIn("site:linkedin.com/in", joined)
        self.assertIn("victim.com", joined)
        self.assertIn("filetype:pdf", joined)


class TestIntegration(unittest.TestCase):
    def test_full_pipeline(self):
        names = "Jane Smith\nJohn A. Doe\n".split("\n")
        rows = build_username_report(names, "example.org")
        self.assertGreater(len(rows), 10)
        for row in rows:
            self.assertLessEqual(len(row["candidate_username"]), MAX_SAM_ACCOUNT_LEN)


class TestTargetParsing(unittest.TestCase):
    def test_parse_domain(self):
        result = parse_target("victim.com")
        self.assertEqual(result["type"], "domain")
        self.assertEqual(result["domain"], "victim.com")
        self.assertEqual(result["ip"], "")

    def test_parse_url(self):
        result = parse_target("https://www.victim.com/path")
        self.assertEqual(result["type"], "url")
        self.assertEqual(result["domain"], "www.victim.com")

    def test_parse_ip(self):
        result = parse_target("1.1.1.1")
        self.assertEqual(result["type"], "ip")
        self.assertEqual(result["ip"], "1.1.1.1")
        self.assertEqual(result["domain"], "1.1.1.1")

    def test_parse_url_with_path(self):
        result = parse_target("https://victim.com/admin/login")
        self.assertEqual(result["type"], "url")
        self.assertEqual(result["domain"], "victim.com")

    def test_is_ip_address_true(self):
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("::1"))

    def test_is_ip_address_false(self):
        self.assertFalse(is_ip_address("victim.com"))
        self.assertFalse(is_ip_address("not an ip"))


class TestEscapeHtml(unittest.TestCase):
    def test_escapes_special_chars(self):
        self.assertEqual(escape_html("<script>"), "&lt;script&gt;")
        self.assertEqual(escape_html("&"), "&amp;")
        self.assertEqual(escape_html('"quote"'), "&quot;quote&quot;")


class TestHtmlReport(unittest.TestCase):
    def test_render_html_report_domain(self):
        report = {
            "target": "example.com",
            "target_type": "domain",
            "domain": "example.com",
            "dns": {"A": ["1.2.3.4"]},
            "whois": {"registrar": "Example Registrar"},
            "manual_search_dorks": ["site:example.com"],
            "note": "test note",
        }
        html = render_html_report(report)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("example.com", html)
        self.assertIn("DNS", html)
        self.assertIn("Manual Search Dorks", html)

    def test_render_html_report_ip(self):
        report = {
            "target": "1.1.1.1",
            "target_type": "ip",
            "domain": "1.1.1.1",
            "ip_address": "1.1.1.1",
            "reverse_dns": ["one.one.one.one."],
            "ip_whois": {"org": "Cloudflare"},
            "dns": {},
            "whois": {},
            "subdomains_via_crtsh": [],
            "web_footprint": {"skipped": "no domain"},
            "hibp_breach_check": {"skipped": "no key"},
            "manual_search_dorks": [],
            "note": "test note",
        }
        html = render_html_report(report)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("1.1.1.1", html)
        self.assertIn("IP Address", html)
        self.assertIn("Reverse DNS", html)


class TestEnvironmentReport(unittest.TestCase):
    def test_build_environment_report_domain(self):
        target_info = parse_target("example.com")
        report = build_environment_report(target_info, "", "")
        self.assertEqual(report["target_type"], "domain")
        self.assertEqual(report["domain"], "example.com")
        self.assertIn("dns", report)
        self.assertIn("whois", report)
        self.assertIn("subdomains_via_crtsh", report)

    def test_build_environment_report_ip(self):
        target_info = parse_target("1.1.1.1")
        report = build_environment_report(target_info, "", "")
        self.assertEqual(report["target_type"], "ip")
        self.assertIn("ip_address", report)
        self.assertIn("reverse_dns", report)
        self.assertIn("ip_whois", report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
