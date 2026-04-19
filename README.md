# CyberTool

<img width="1880" height="1326" alt="Image" src="https://github.com/user-attachments/assets/9885c9eb-ceff-4c95-ad4a-584f68553514" />

A self-hosted, all-in-one penetration testing web app that runs locally on `localhost:5000`. Built with Flask and plain JavaScript — no frameworks, no cloud, no data leaves your machine.

> **For authorized security testing only.** Only use against systems you own or have explicit written permission to test.

---

## Features

| Tool | Description |
|------|-------------|
| **Port Scanner** | TCP port scanner with preset ranges (Top 100, Common, Full 1–65535) |
| **Nmap** | Run Nmap with a command builder, saved presets, and Markdown report export |
| **DNS Lookup** | A/AAAA/MX/NS/CNAME/TXT record lookup with error surfacing |
| **Subdomain Enumeration** | DNS brute-force with takeover detection (GitHub Pages, Heroku, Shopify, Fastly, and more) |
| **Directory Brute Force** | HTTP path discovery with recursive scanning, proxy support, and custom wordlists |
| **Web Headers** | Analyze HTTP response headers for security misconfigurations |
| **SSL Inspector** | Certificate expiry, SANs, issuer, protocol version, cipher strength, and weakness flags |
| **Web Login Brute Force** | Form-based credential stuffing with custom wordlists and proxy support |
| **SQL Injection Scanner** | Error-based, time-based blind, and differential SQLi detection; auto-mode tests all params from a wordlist |
| **Hash Identifier & Cracker** | Identify MD5/SHA-1/SHA-256/SHA-512/bcrypt; crack against a wordlist |
| **Encoder / Decoder** | Base64, Base32, Base58, URL, HTML, Hex, ROT13, MD5/SHA hashing |
| **Reverse Shell Generator** | One-click shell commands for Bash, Python, PHP, PowerShell, Netcat, Ruby, Perl, Socat |
| **CVE Search** | Search and save CVEs with CVSS scores and descriptions |
| **Robots.txt Fetcher** | Fetch and display `robots.txt` for a target |
| **CIDR Calculator** | Network range, broadcast, first/last host, and usable IP count |
| **Wordlists Manager** | Upload, view, and remove custom `.txt` wordlists used across all scanning tools |
| **Reports** | Save, view, export (Markdown + HTML), and delete per-tool reports |
| **Activity Log** | Persistent session log of all actions; downloadable |

---

## Quick Start

### Requirements

- Python 3.9+
- Nmap (optional — only needed for the Nmap tab)

### Install & Run

```bash
git clone https://github.com/yourusername/cybertool.git
cd cybertool
pip install -r requirements.txt
python app.py
```

Then open [http://localhost:5000](http://localhost:5000) in your browser.

---

## Project Structure

```
cybertool/
├── app.py                  # Flask app, all API routes
├── requirements.txt
├── modules/
│   ├── utils.py            # Shared: user-agent rotation, wordlist loader, hash helpers, proxy builder
│   ├── port_scanner.py     # TCP port scanner
│   ├── dns_lookup.py       # DNS record lookup
│   ├── subdomain_enum.py   # Subdomain brute-force + takeover detection
│   ├── dir_bruteforce.py   # Directory/path brute-force with recursive support
│   ├── web_headers.py      # HTTP header analysis
│   ├── web_brute.py        # Web login brute-force
│   ├── ssl_inspector.py    # SSL/TLS certificate inspection (built-in ssl module, no extra deps)
│   ├── sqli_scanner.py     # SQL injection scanner (error-based, time-based blind, differential)
│   ├── hash_cracker.py     # Hash cracking
│   ├── hash_tools.py       # Hash identification
│   ├── encoder.py          # Encode/decode operations
│   └── vuln_scanner.py     # CVE lookup helpers
├── wordlists/
│   ├── common_dirs.txt     # Built-in directory wordlist
│   ├── subdomains.txt      # Built-in subdomain wordlist
│   ├── passwords.txt       # Built-in password wordlist
│   ├── sqli_params.txt     # Parameter names for SQLi auto-scan
│   └── custom/             # Uploaded wordlists (gitignored)
├── static/
│   ├── css/style.css
│   └── js/app.js
├── templates/
│   └── index.html
├── reports/                # Saved JSON reports (gitignored)
├── logs/                   # Activity log (gitignored)
└── tests/
    └── test_modules.py     # 28 unit tests
```

---

## Configuration

### Adding Custom Wordlists

Go to the **Wordlists** tab in the app and upload any `.txt` file (one entry per line). It will automatically appear in the wordlist dropdown for Dir Brute, Subdomain Enum, Web Brute, and Hash Cracker.

You can also edit `wordlists/sqli_params.txt` directly to add or remove parameter names for the SQLi auto-scan mode. Lines starting with `#` are treated as comments.

### Proxy Support

Dir Brute, Web Brute, and SQL Injection all support routing traffic through an HTTP proxy (e.g. Burp Suite at `http://127.0.0.1:8080`).

---

## Security Notes

- Runs entirely on localhost — no external services, no telemetry
- Nmap commands are validated with argument whitelisting before execution
- File paths are sanitized with `os.path.basename` + `os.path.abspath` to prevent traversal
- Rate limiting is applied to all scanning endpoints (port scan, subdomain enum, dir brute, web brute, SQLi, hash crack)
- All state is stored in memory with thread-safe locking

---

## Running Tests

```bash
python -m pytest tests/test_modules.py -v
```

28 tests covering utils, port scanner, hash tools, and encoder.

---

## Disclaimer

This tool is intended for **authorized penetration testing, CTF competitions, and educational use only**. Unauthorized use against systems you do not own is illegal. The author assumes no liability for misuse.
