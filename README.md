# AD OSINT Recon Tool

A reconnaissance helper for **authorized** Active Directory penetration tests and red team engagements.

## What It Does

1. **Username generation** — turns a list of employee full names into likely Active Directory / O365 username formats (e.g. `first.last`, `flast`, `lastf`, `smithj`). Covers common sAMAccountName conventions (<=20 chars, lowercase). Includes nickname expansion (Bill → William) and double-surname handling (Garcia Lopez).

2. **Environment scan** — gathers PUBLIC information about a target domain, URL, or IP address using passive sources only:
   - Auto-detects target type (domain, URL, or IP address)
   - DNS records (A, AAAA, MX, NS, TXT/SPF/DMARC)
   - Certificate Transparency logs (crt.sh) for subdomain discovery
   - WHOIS registration data (domain and IP)
   - Reverse DNS lookups for IP targets
   - Public web footprint (security.txt, robots.txt)
   - Optional HaveIBeenPwned breach check
   - Manual search-engine dork strings
   - Report output in **JSON** and/or **HTML** format

## Important – Scope & Ethics

- **Does NOT** perform password spraying, brute forcing, or any authentication attempts against a live AD/Entra ID/O365 environment.
- **Does NOT** scrape LinkedIn or other sites that prohibit automated scraping. Feed it names manually.
- **Does NOT** touch the target's internal network. Everything here is passive/public-source reconnaissance.
- Only use this against organizations you are **explicitly authorized** to test (signed engagement letter / rules of engagement in hand).

## Project Structure

```
ADPentesting/
├── README.md                      # This file
├── requirements.txt               # Python dependencies
├── .gitignore                     # Python cache / build artifacts
├── ad_osint_recon.py              # CLI tool (username generation + environment scan)
├── ad_username_generator.html     # Standalone web UI (no dependencies)
├── examples/
│   └── sample_names.txt           # Sample input file with edge-case names
└── tests/
    └── test_username_generation.py  # Unit tests (39 tests)
```

## Installation

```bash
git clone <repo-url>
cd ADPentesting
pip install -r requirements.txt
pip install pytest          # for running tests
```

### Requirements

- Python 3.10+
- `dnspython` – DNS record lookups and reverse DNS
- `python-whois` – WHOIS data (domain and IP)
- `requests` – HTTP queries (crt.sh, web footprint, HIBP)
- `pytest` – for running tests (optional)

## Usage

### CLI (ad_osint_recon.py)

```bash
# Generate usernames from a names file
python3 ad_osint_recon.py usernames --names names.txt --domain victim.com --out usernames.csv

# Passive environment scan (domain, URL, or IP — auto-detected)
python3 ad_osint_recon.py environment-scan --target https://victim.com --out report.json --format json

# Both JSON and HTML reports
python3 ad_osint_recon.py environment-scan --target 1.2.3.4 --out report --format both

# Legacy domain-recon (also supports HTML output)
python3 ad_osint_recon.py domain-recon --domain victim.com --out domain_report.html

# Both username generation and domain recon in one JSON report
python3 ad_osint_recon.py full --names names.txt --domain victim.com --out full_report.json
```

#### Subcommands

| Command | Description |
|---|---|
| `usernames` | Generate AD username candidates from a names file |
| `domain-recon` | Passive OSINT on a target domain (legacy alias) |
| `environment-scan` | Passive OSINT on a domain, URL, or IP address target |
| `full` | Run both username generation and environment recon |

#### Arguments

| Flag | Required | Description |
|---|---|---|
| `--names` | Yes (usernames, full) | Path to a text file with one full name per line |
| `--domain` | Yes (full) | Target domain for username emails (e.g. `victim.com`) |
| `--target` | Yes (environment-scan) | Target domain (`victim.com`), URL (`https://victim.com`), or IP (`1.2.3.4`) |
| `--out` | Yes | Output path (`.csv`, `.json`, or `.html`) |
| `--format` | No (env-scan) | Output format: `json`, `html`, or `both` (default: json) |
| `--company-name` | No | Company name for dork generation (defaults to domain root) |
| `--hibp-key` | No | Your own HaveIBeenPwned API key (optional) |

### Web UI (ad_username_generator.html)

Open `ad_username_generator.html` in any modern browser. No server or dependencies required. Generates username candidates locally — nothing is sent over the network.

### Running Tests

```bash
python3 -m pytest tests/test_username_generation.py -v
```

## names.txt Format

One full name per line:

```
Jane Smith
John A. Doe
Mary-Anne O'Brien
```

## Output

### Username CSV / JSON

| full_name | candidate_username | candidate_email |
|---|---|---|
| Jane Smith | jane.smith | jane.smith@victim.com |
| Jane Smith | j.smith | j.smith@victim.com |
| ... | ... | ... |

Usernames are truncated to 20 characters (sAMAccountName limit).

### Environment Recon JSON

```json
{
  "target": "example.com",
  "target_type": "domain",
  "domain": "example.com",
  "dns": { "A": [...], "MX": [...], "TXT": [...], "SPF": [...], "DMARC": [...] },
  "subdomains_via_crtsh": ["sub1.example.com", ...],
  "whois": { "registrar": "...", "creation_date": "...", "expiration_date": "...", "name_servers": [...], "org": "..." },
  "web_footprint": { "/.well-known/security.txt": {...}, "/robots.txt": {...} },
  "manual_search_dorks": ["site:linkedin.com/in \"example\"", ...],
  "note": "Passive/public sources only."
}
```

For IP targets, the report includes `ip_address`, `reverse_dns`, and `ip_whois` fields.

### Environment Recon HTML

The `--format html` option produces a styled, self-contained HTML report with sections for each data category, rendered as tables and lists. Open the output file directly in any browser.

## Username Patterns Generated

The Python CLI generates the following patterns per name:

| Pattern | Example |
|---|---|
| `first.last` | `jane.smith` |
| `firstlast` | `janesmith` |
| `flast` | `jsmith` |
| `firstl` | `janes` |
| `lastf` | `smithj` |
| `last.first` | `smith.jane` |
| `lastfirst` | `smithjane` |
| `first_last` | `jane_smith` |
| `last_first` | `smith_jane` |
| `f.m.last` | `j.a.smith` |
| `fmlast` | `jasmith` |
| Double-surname variants | `jane.garcia.lopez`, `jgarcialopez` |

The web UI generates the same patterns via JavaScript, with the ability to toggle individual patterns on/off and enable/disable nickname expansion.

## Legal Disclaimer

This tool is for **authorized security testing only**. Passive OSINT on a domain or IP you do not own or lack permission to assess may violate laws or terms of service in your jurisdiction. Always obtain explicit written authorization before use.
