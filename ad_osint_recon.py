#!/usr/bin/env python3
"""
ad_osint_recon.py
==================

A reconnaissance helper for AUTHORIZED Active Directory penetration tests
and red team engagements.

WHAT THIS TOOL DOES
--------------------
1. Username generation: turns a list of employee full names into the set
   of Active Directory username formats an org is likely using
   (first.last, flast, lastf, etc.), following common sAMAccountName
   conventions (<=20 chars, lowercase, no special formatting quirks).
2. Passive domain OSINT: gathers PUBLIC information about a target domain
   or IP address using passive sources only:
     - DNS records (A, AAAA, MX, NS, TXT/SPF/DMARC)
     - Certificate Transparency logs (crt.sh) for subdomain discovery
     - WHOIS registration data (domain and IP)
     - Reverse DNS lookups for IP targets
     - Public web footprint (security.txt, robots.txt)
3. Environment scan target can be a domain, URL, or IP address. The tool
   auto-detects the type and applies the appropriate reconnaissance functions.
4. Report output in JSON and/or HTML format.

WHAT THIS TOOL DELIBERATELY DOES NOT DO
----------------------------------------
- It does NOT perform password spraying, brute forcing, or any
  authentication attempts against a live AD/Entra ID/O365 environment.
- It does NOT scrape LinkedIn or other sites that prohibit automated
  scraping in their ToS. Feed it names manually (e.g. extracted from
  a legitimate people-search step you've already done).
- It does NOT touch the target's internal network. Everything here is
  passive/public-source reconnaissance.

Turning the username list this tool produces into an actual login
attempt against a client's environment is a separate, much more
sensitive step that requires explicit written authorization, careful
lockout-threshold awareness, and (ideally) coordination with the client's
blue team. That step is out of scope for this script by design.

LEGAL / ETHICAL REQUIREMENT
-----------------------------
Only use this against organizations you are explicitly authorized to
test (signed engagement letter / rules of engagement in hand). Passive
OSINT on a domain you don't own or have permission to assess may still
violate laws or terms of service in your jurisdiction.

DEPENDENCIES
------------
    pip install dnspython python-whois requests

USAGE
-----
    # Generate usernames from a names file
    python3 ad_osint_recon.py usernames --names names.txt --domain victim.com --out usernames.csv

    # Passive environment scan (auto-detects domain/URL/IP)
    python3 ad_osint_recon.py environment-scan --target https://victim.com --out report.json --format json

    # Passive environment scan with HTML report
    python3 ad_osint_recon.py environment-scan --target 1.2.3.4 --out report.html --format html

    # Both, in one report
    python3 ad_osint_recon.py full --names names.txt --domain victim.com --out full_report.json

names.txt format (one per line):
    Jane Smith
    John A. Doe
    Mary-Anne O'Brien
"""

import argparse
import csv
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Set
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Username generation
# ---------------------------------------------------------------------------

MAX_SAM_ACCOUNT_LEN = 20  # AD sAMAccountName hard limit

# Common nickname -> formal name mappings (helps catch "Bill" for "William", etc.)
# so generated usernames also cover the formal variant people often actually
# register under in AD/HR systems.
NICKNAME_MAP = {
    "bill": "william",
    "will": "william",
    "bob": "robert",
    "rob": "robert",
    "bobby": "robert",
    "dick": "richard",
    "rick": "richard",
    "rich": "richard",
    "jim": "james",
    "jimmy": "james",
    "jack": "john",
    "johnny": "john",
    "mike": "michael",
    "mikey": "michael",
    "steve": "steven",
    "dave": "david",
    "dan": "daniel",
    "danny": "daniel",
    "tom": "thomas",
    "tommy": "thomas",
    "chris": "christopher",
    "greg": "gregory",
    "ken": "kenneth",
    "ted": "edward",
    "ed": "edward",
    "eddie": "edward",
    "andy": "andrew",
    "drew": "andrew",
    "matt": "matthew",
    "nick": "nicholas",
    "tony": "anthony",
    "sam": "samuel",
    "sammy": "samuel",
    "joe": "joseph",
    "joey": "joseph",
    "beth": "elizabeth",
    "liz": "elizabeth",
    "eliza": "elizabeth",
    "kate": "katherine",
    "katie": "katherine",
    "kathy": "katherine",
    "meg": "margaret",
    "peggy": "margaret",
    "sue": "susan",
    "suzy": "susan",
    "jen": "jennifer",
    "jenny": "jennifer",
    "cindy": "cynthia",
    "deb": "deborah",
    "debbie": "deborah",
    "pat": "patricia",
    "trish": "patricia",
    "vicky": "victoria",
    "vic": "victoria",
    "abby": "abigail",
}


def _clean_name_part(part: str) -> str:
    """Lowercase, strip accents/punctuation that AD usernames don't carry."""
    part = part.strip().lower()
    part = re.sub(r"[^a-z\-']", "", part)
    part = part.replace("'", "").replace("-", "")
    return part


@dataclass
class NameParts:
    first: str
    last: str
    middle: str = ""
    last2: str = ""  # second surname, for double-barrelled names (e.g. Garcia Lopez)

    @classmethod
    def parse(cls, full_name: str) -> "NameParts":
        # Hyphenated/double surnames get split back out for extra patterns,
        # but _clean_name_part already strips hyphens for the primary token.
        raw_tokens = [t for t in full_name.strip().replace("-", " ").split() if t]
        tokens = [t for t in full_name.strip().split() if t]
        if len(tokens) == 0:
            raise ValueError(f"Empty name: {full_name!r}")
        if len(tokens) == 1:
            return cls(first=_clean_name_part(tokens[0]), last="")

        first = _clean_name_part(raw_tokens[0])
        last = _clean_name_part(raw_tokens[-1])
        middle = ""
        last2 = ""
        if len(raw_tokens) >= 3:
            # For a 3-token name (e.g. "Maria Garcia Lopez") the token right
            # after the first name is BOTH a plausible middle name (Western
            # convention) AND a plausible first/paternal surname (Spanish
            # double-surname convention). We can't know which without more
            # context, so we deliberately keep middle and last2 as
            # independent fields covering both interpretations rather than
            # letting one suppress the other - generate_usernames() then
            # produces patterns for both.
            middle = _clean_name_part(raw_tokens[1])
            last2 = _clean_name_part(raw_tokens[-2])
        return cls(first=first, last=last, middle=middle, last2=last2)

    def name_variants(self) -> List[str]:
        """First-name variants including nickname<->formal-name expansion."""
        variants = {self.first}
        formal = NICKNAME_MAP.get(self.first)
        if formal:
            variants.add(formal)
        # also check reverse: is `first` itself a formal name with a nickname?
        for nick, form in NICKNAME_MAP.items():
            if form == self.first:
                variants.add(nick)
        return sorted(variants)


def generate_usernames(name: NameParts) -> Set[str]:
    """Generate common AD/O365 username convention candidates for one person,
    including nickname and double-surname variants."""
    candidates: Set[str] = set()

    for f in name.name_variants():
        l, m, l2 = name.last, name.middle, name.last2
        if not f or not l:
            candidates.add(f or l)
            continue
        candidates.update(
            {
                f"{f}.{l}",  # jane.smith
                f"{f}{l}",  # janesmith
                f"{f[0]}{l}",  # jsmith
                f"{f}{l[0]}",  # janes
                f"{l}{f[0]}",  # smithj
                f"{l}.{f}",  # smith.jane
                f"{l}{f}",  # smithjane
                f"{f[0]}.{l}",  # j.smith
                f"{f}_{l}",  # jane_smith
                f"{l}_{f}",  # smith_jane
                f"{f[0]}{m[0]}{l}" if m else "",  # jasmith (middle initial)
                f"{f}.{m}.{l}" if m else "",  # jane.a.smith
            }
        )
        if l2 and l2 != l:
            # double-barrelled surname patterns, e.g. Garcia Lopez
            candidates.update(
                {
                    f"{f}.{l2}{l}",  # jane.garcialopez (no separator on surname)
                    f"{f}.{l2}.{l}",  # jane.garcia.lopez
                    f"{f[0]}{l2}{l}",  # jgarcialopez
                    f"{f}.{l2}",  # jane.garcia (goes by first surname only)
                }
            )

    candidates.discard("")
    candidates.discard(None)
    # Enforce sAMAccountName length limit
    return {c[:MAX_SAM_ACCOUNT_LEN] for c in candidates if c}


def load_names(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def build_username_report(names: List[str], domain: str = "") -> List[Dict]:
    rows = []
    for raw in names:
        try:
            parts = NameParts.parse(raw)
        except ValueError:
            continue
        for uname in sorted(generate_usernames(parts)):
            row = {
                "full_name": raw,
                "candidate_username": uname,
            }
            if domain:
                row["candidate_email"] = f"{uname}@{domain}"
            rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Target parsing (domain / URL / IP address)
# ---------------------------------------------------------------------------


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD OSINT Recon Report</title>
<style>
:root {{
  --bg: #0f1115;
  --panel: #171a21;
  --border: #2a2f3a;
  --text: #e6e8eb;
  --muted: #9aa3af;
  --accent: #5b8cff;
  --danger: #ff6b6b;
  --warn: #f5a623;
  --mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
}}
* {{ box-sizing: border-box; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  margin: 0;
  padding: 24px;
  line-height: 1.5;
}}
.wrap {{ max-width: 960px; margin: 0 auto; }}
h1 {{ font-size: 1.4rem; margin-bottom: 4px; }}
h2 {{
  font-size: 1.1rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: 6px;
  margin-top: 24px;
}}
.subtitle {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 20px; }}
.banner {{
  background: #2a1f12;
  border: 1px solid #6b4a1b;
  color: #e8c68a;
  padding: 12px 14px;
  border-radius: 8px;
  font-size: 0.85rem;
  margin-bottom: 20px;
}}
.panel {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 18px;
  margin-bottom: 18px;
}}
code, pre {{
  font-family: var(--mono);
  background: #0d0f13;
  border-radius: 4px;
}}
code {{ padding: 1px 5px; }}
pre {{
  padding: 12px;
  overflow-x: auto;
  border: 1px solid var(--border);
  font-size: 0.85rem;
}}
table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.85rem; }}
th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }}
th {{ color: var(--muted); font-weight: 600; }}
.tag {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}}
.tag-ok {{ background: #1a3a1a; color: #4ade80; }}
.tag-warn {{ background: #332701; color: var(--warn); }}
.tag-err {{ background: #3a1a1a; color: var(--danger); }}
pre-wrap {{ white-space: pre-wrap; word-break: break-word; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>AD OSINT Recon Report</h1>
  <div class="subtitle">Passive/public-source reconnaissance report</div>
  <div class="banner">
    &uarr; Use only against systems you are explicitly authorized to assess.
    This tool uses passive/public sources only — no connections were made to
    internal AD infrastructure.
  </div>
  {content}
</div>
</body>
</html>"""


def is_ip_address(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def parse_target(target: str) -> Dict[str, str]:
    """Parse a user-supplied target into a normalized form.

    Accepts bare domains (victim.com), full URLs (https://victim.com/path),
    or IP addresses (1.2.3.4). Returns a dict with keys:
      - target: the original input
      - type: 'domain', 'ip', or 'url'
      - domain: the extracted domain name
      - ip: the IP address (for IP targets)
      - url: the normalized URL (for URL targets)
    """
    target = target.strip()
    if not target:
        return {"target": "", "type": "domain", "domain": "", "ip": "", "url": ""}

    if is_ip_address(target):
        return {
            "target": target,
            "type": "ip",
            "domain": target,
            "ip": target,
            "url": "",
        }

    if "://" not in target:
        candidate = target
    else:
        parsed = urlparse(target)
        candidate = parsed.netloc or parsed.path

    candidate = candidate.rstrip("/").split(":")[0]

    if is_ip_address(candidate):
        return {
            "target": target,
            "type": "ip",
            "domain": candidate,
            "ip": candidate,
            "url": target,
        }

    return {
        "target": target,
        "type": "url" if "://" in target else "domain",
        "domain": candidate,
        "ip": "",
        "url": target,
    }


def reverse_dns_lookup(ip: str) -> List[str]:
    """Reverse DNS resolution — passive, uses standard PTR lookups."""
    try:
        import dns.resolver
    except ImportError:
        return ["dnspython not installed (pip install dnspython)"]

    reversed_ip = ipaddress.ip_address(ip).reverse_pointer
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(reversed_ip, "PTR")
        return [str(r).strip() for r in answers]
    except Exception as e:
        return [f"reverse DNS lookup failed or no record ({type(e).__name__})"]


def ip_whois_lookup(ip: str) -> Dict:
    """Public IP WHOIS data."""
    try:
        import whois
    except ImportError:
        return {"error": "python-whois not installed (pip install python-whois)"}

    try:
        w = whois.whois(ip)
        return {
            "registrar": str(w.get("registrar")),
            "creation_date": str(w.get("creation_date")),
            "expiration_date": str(w.get("expiration_date")),
            "name_servers": [str(ns) for ns in (w.get("name_servers") or [])],
            "org": str(w.get("org")),
            "net_name": str(w.get("net_name")),
            "country": str(w.get("country")),
        }
    except Exception as e:
        return {"error": f"IP whois lookup failed: {e}"}


# ---------------------------------------------------------------------------
# Passive domain OSINT
# ---------------------------------------------------------------------------


def dns_recon(domain: str) -> Dict:
    """Pull public DNS records. Passive - standard DNS lookups only."""
    try:
        import dns.resolver
    except ImportError:
        return {"error": "dnspython not installed (pip install dnspython)"}

    result: Dict[str, object] = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]
    resolver = dns.resolver.Resolver()
    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            result[rtype] = [str(r).strip() for r in answers]
        except Exception as e:
            result[rtype] = f"lookup failed or no record ({type(e).__name__})"

    # Pull out SPF/DMARC specifically since they matter for phishing-sim planning
    txt_records = result.get("TXT", [])
    if isinstance(txt_records, list):
        result["SPF"] = [t for t in txt_records if "v=spf1" in t.lower()]
    try:
        dmarc = resolver.resolve(f"_dmarc.{domain}", "TXT")
        result["DMARC"] = [str(r).strip() for r in dmarc]
    except Exception:
        result["DMARC"] = "not found"

    return result


def crtsh_subdomains(domain: str) -> List[str]:
    """Passive subdomain discovery via Certificate Transparency logs (crt.sh)."""
    try:
        import requests
    except ImportError:
        return ["requests not installed (pip install requests)"]

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        subs = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for line in name_value.split("\n"):
                line = line.strip().lower()
                if line and not line.startswith("*"):
                    subs.add(line)
        return sorted(subs)
    except Exception as e:
        return [f"crt.sh lookup failed: {e}"]


def whois_lookup(domain: str) -> Dict:
    """Public WHOIS registration data."""
    try:
        import whois
    except ImportError:
        return {"error": "python-whois not installed (pip install python-whois)"}

    try:
        w = whois.whois(domain)
        return {
            "registrar": str(w.get("registrar")),
            "creation_date": str(w.get("creation_date")),
            "expiration_date": str(w.get("expiration_date")),
            "name_servers": [str(ns) for ns in (w.get("name_servers") or [])],
            "org": str(w.get("org")),
        }
    except Exception as e:
        return {"error": f"whois lookup failed: {e}"}


def web_footprint(domain: str) -> Dict:
    """Lightweight passive check of a couple of standard, publicly-served
    files. A plain GET to files a site chooses to publish is not scanning
    or exploitation - it's the same request any browser makes."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed (pip install requests)"}

    result = {}
    for path in ["/.well-known/security.txt", "/robots.txt"]:
        url = f"https://{domain}{path}"
        try:
            resp = requests.get(url, timeout=10)
            result[path] = {
                "status": resp.status_code,
                "excerpt": resp.text[:500] if resp.status_code == 200 else None,
            }
        except Exception as e:
            result[path] = {"error": str(e)}
    return result


def hibp_domain_breach_check(domain: str, api_key: str) -> Dict:
    """Check HaveIBeenPwned for known breaches associated with the domain.
    Requires your own HIBP API key (https://haveibeenpwned.com/API/Key) -
    this tool does not ship or embed one. Useful for assessing how exposed
    an org's credentials already are, which informs risk framing for a
    password-spray recommendation you'd make to the client separately."""
    try:
        import requests
    except ImportError:
        return {"error": "requests not installed (pip install requests)"}
    if not api_key:
        return {"skipped": "no --hibp-key provided"}

    url = f"https://haveibeenpwned.com/api/v3/breaches"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "ad-osint-recon-authorized-pentest",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        breaches = resp.json()
        domain_breaches = [
            b["Name"] for b in breaches if b.get("Domain", "").lower() == domain.lower()
        ]
        return {"matching_breaches": domain_breaches}
    except Exception as e:
        return {"error": f"HIBP lookup failed: {e}"}


def build_search_dorks(domain: str, company_name: str = "") -> List[str]:
    """Build search-engine query STRINGS for manual OSINT research.
    These are just text you paste into a search engine yourself - this
    function does not query, scrape, or automate anything."""
    company = company_name or domain.split(".")[0]
    return [
        f'site:linkedin.com/in "{company}"',
        f"site:{domain} filetype:pdf",
        f"site:{domain} filetype:xlsx OR filetype:docx",
        f'"{company}" "@{domain}" -site:{domain}',
        f'site:pastebin.com "{domain}"',
        f'site:github.com "{domain}" password OR secret OR api_key',
        f'site:trello.com "{company}"',
        f'intitle:"index of" "{domain}"',
        f'site:{domain} "employee handbook" OR "org chart"',
    ]


def build_environment_report(
    target_info: Dict[str, str], company_name: str = "", hibp_key: str = ""
) -> Dict:
    """Build a full environment scan report for a domain, URL, or IP target."""
    domain = target_info.get("domain", "")
    ip = target_info.get("ip", "")
    target_type = target_info.get("type", "domain")

    report: Dict = {
        "target": target_info.get("target", ""),
        "target_type": target_type,
        "domain": domain,
    }

    if ip:
        report["ip_address"] = ip
        report["reverse_dns"] = reverse_dns_lookup(ip)
        report["ip_whois"] = ip_whois_lookup(ip)

    report["dns"] = dns_recon(domain) if domain else {}
    report["subdomains_via_crtsh"] = (
        crtsh_subdomains(domain) if domain and target_type != "ip" else []
    )
    report["whois"] = (
        ip_whois_lookup(ip) if ip else whois_lookup(domain) if domain else {}
    )
    if domain and not ip:
        report["web_footprint"] = web_footprint(domain)
    else:
        report["web_footprint"] = {"skipped": "no domain for web footprint"}
    report["hibp_breach_check"] = (
        hibp_domain_breach_check(domain, hibp_key)
        if hibp_key and domain
        else {"skipped": "no --hibp-key provided"}
    )
    report["manual_search_dorks"] = (
        build_search_dorks(domain, company_name) if domain and not ip else []
    )
    report["note"] = (
        "Passive/public sources only. No connections were made to "
        "internal AD infrastructure. Search dorks are for you to "
        "paste into a search engine manually, not automated queries."
    )
    return report


def build_domain_report(
    domain: str, company_name: str = "", hibp_key: str = ""
) -> Dict:
    target_info = parse_target(domain)
    return build_environment_report(target_info, company_name, hibp_key)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def write_csv(rows: List[Dict], path: str) -> None:
    if not rows:
        print("No rows to write.", file=sys.stderr)
        return
    fieldnames = sorted({k for row in rows for k in row.keys()})
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_json(obj, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=str)


def _render_section(title: str, data: object) -> str:
    """Render a section of the HTML report."""
    if isinstance(data, dict):
        if len(data) == 0:
            return f"<h2>{title}</h2>\n<p class='muted'>No data</p>"
        rows = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                nested = json.dumps(value, indent=2, default=str)
                rows.append(
                    f"<tr><td style='width:40%;'><code>{escape_html(str(key))}</code></td>"
                    f"<td><pre class='pre-wrap'>{escape_html(nested)}</pre></td></tr>"
                )
            else:
                rows.append(
                    f"<tr><td style='width:40%;'><code>{escape_html(str(key))}</code></td>"
                    f"<td>{escape_html(str(value))}</td></tr>"
                )
        table = (
            "<table><thead><tr><th>Field</th><th>Value</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )
        return f"<h2>{escape_html(title)}</h2>\n<div class='panel'>{table}</div>"
    elif isinstance(data, list):
        if len(data) == 0:
            return f"<h2>{escape_html(title)}</h2>\n<p class='muted'>No data</p>"
        items = "".join(f"<li>{escape_html(str(item))}</li>" for item in data)
        return (
            f"<h2>{escape_html(title)}</h2>\n"
            f"<div class='panel'><ul>{items}</ul></div>"
        )
    else:
        return (
            f"<h2>{escape_html(title)}</h2>\n"
            f"<div class='panel pre-wrap'>{escape_html(str(data))}</div>"
        )


def escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def render_html_report(report: Dict) -> str:
    """Render a full environment scan report as an HTML page."""
    sections = []
    target = report.get("target", "")
    target_type = report.get("target_type", "domain")
    domain = report.get("domain", "")

    sections.append(
        f"<div class='panel'><h2>Target</h2>"
        f"<table><tbody>"
        f"<tr><td>Target</td><td><code>{escape_html(target)}</code></td></tr>"
        f"<tr><td>Type</td><td>"
        f"<span class='tag tag-ok'>{escape_html(target_type)}</span>"
        f"</td></tr>"
    )
    if domain and target_type == "ip":
        sections.append(
            f"<tr><td>IP Address</td><td><code>{escape_html(report.get('ip_address', ''))}</code></td></tr>"
        )
    sections.append("</tbody></table></div>")

    section_keys = [
        ("IP Address", "ip_address"),
        ("Reverse DNS", "reverse_dns"),
        ("IP WHOIS", "ip_whois"),
        ("DNS", "dns"),
        ("Subdomains (crt.sh)", "subdomains_via_crtsh"),
        ("WHOIS", "whois"),
        ("Web Footprint", "web_footprint"),
        ("HIBP Breach Check", "hibp_breach_check"),
        ("Manual Search Dorks", "manual_search_dorks"),
    ]

    for title, key in section_keys:
        if key in report:
            sections.append(_render_section(title, report[key]))

    if "note" in report:
        sections.append(
            f"<div class='panel'><h2>Note</h2><p class='muted'>{escape_html(report['note'])}</p></div>"
        )

    return HTML_TEMPLATE.format(content="\n".join(sections))


def write_html(report: Dict, path: str) -> None:
    """Write a report as an HTML file."""
    html = render_html_report(report)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="AD username-convention generator + passive domain OSINT "
        "for AUTHORIZED penetration test engagements only."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_user = sub.add_parser(
        "usernames", help="Generate AD username candidates from a names file"
    )
    p_user.add_argument(
        "--names", required=True, help="Path to a text file, one full name per line"
    )
    p_user.add_argument(
        "--domain", default="", help="Email domain to append (e.g. victim.com)"
    )
    p_user.add_argument("--out", required=True, help="Output path (.csv or .json)")

    p_domain = sub.add_parser("domain-recon", help="Passive OSINT on a target domain")
    p_domain.add_argument("--domain", required=True)
    p_domain.add_argument(
        "--company-name",
        default="",
        help="Company name for dork generation (defaults to domain root)",
    )
    p_domain.add_argument(
        "--hibp-key", default="", help="Your own HaveIBeenPwned API key (optional)"
    )
    p_domain.add_argument("--out", required=True, help="Output path (.json or .html)")

    p_scan = sub.add_parser(
        "environment-scan",
        help="Passive OSINT on a domain, URL, or IP address target",
    )
    p_scan.add_argument(
        "--target",
        required=True,
        help="Target domain (victim.com), URL (https://victim.com), or IP (1.2.3.4)",
    )
    p_scan.add_argument(
        "--company-name",
        default="",
        help="Company name for dork generation (defaults to domain root)",
    )
    p_scan.add_argument(
        "--hibp-key", default="", help="Your own HaveIBeenPwned API key (optional)"
    )
    p_scan.add_argument("--out", required=True, help="Output path (.json or .html)")
    p_scan.add_argument(
        "--format",
        default="json",
        choices=["json", "html", "both"],
        help="Output format: json, html, or both (default: json)",
    )

    p_full = sub.add_parser(
        "full", help="Run both username generation and domain recon"
    )
    p_full.add_argument("--names", required=True)
    p_full.add_argument("--domain", required=True)
    p_full.add_argument("--company-name", default="")
    p_full.add_argument("--hibp-key", default="")
    p_full.add_argument("--out", required=True, help="Output path (.json)")

    args = parser.parse_args()

    print(
        "Reminder: only run this against systems/organizations you are "
        "explicitly authorized to assess.\n",
        file=sys.stderr,
    )

    if args.command == "usernames":
        names = load_names(args.names)
        rows = build_username_report(names, args.domain)
        if args.out.endswith(".json"):
            write_json(rows, args.out)
        else:
            write_csv(rows, args.out)
        print(f"Generated {len(rows)} username candidates -> {args.out}")

    elif args.command == "domain-recon":
        report = build_domain_report(args.domain, args.company_name, args.hibp_key)
        if args.out.endswith(".html"):
            write_html(report, args.out)
        else:
            write_json(report, args.out)
        print(f"Domain recon report -> {args.out}")

    elif args.command == "environment-scan":
        target_info = parse_target(args.target)
        report = build_environment_report(target_info, args.company_name, args.hibp_key)
        out_ext = args.out.rsplit(".", 1)[-1].lower() if "." in args.out else ""
        if args.format == "both":
            base = args.out.rsplit(".", 1)[0] if "." in args.out else args.out
            json_path = f"{base}.json"
            html_path = f"{base}.html"
            write_json(report, json_path)
            write_html(report, html_path)
            print(f"Report written: {json_path}, {html_path}")
        elif args.format == "html" or out_ext == "html":
            write_html(report, args.out)
            print(f"HTML report -> {args.out}")
        else:
            write_json(report, args.out)
            print(f"JSON report -> {args.out}")

    elif args.command == "full":
        names = load_names(args.names)
        report = {
            "usernames": build_username_report(names, args.domain),
            "domain_recon": build_domain_report(
                args.domain, args.company_name, args.hibp_key
            ),
        }
        write_json(report, args.out)
        print(f"Full report -> {args.out}")


if __name__ == "__main__":
    main()
