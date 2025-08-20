![Safe](https://img.shields.io/badge/mode-safe-green)
![OWASP](https://img.shields.io/badge/owasp-top10%20lite-blue)
![Evidence](https://img.shields.io/badge/proof-pack-success)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)


# VulTester Pro — Safe Bug-Bounty Scanner + Proof Pack

**Non-destructive evidence builder for bug-bounty and VRP workflows.**  
Runs OWASP Top-10 lite probes (GET-only) and captures a clean **Proof Pack**:
- `report.html` (ranked findings, vectors, safe curl repros)
- `http_log.json` (HTTP transcript)
- `findings.json` (structured issues)
- `curl_repros.txt` (copy-paste repros)
- `summary.json`
- optional `evidence.zip`

Disclaimer

This project is for authorized security testing only. The authors are not responsible for misuse. By using this tool, you agree to comply with all applicable laws and program policies.

> ⚠️ **Legal**: Use only on assets where you have explicit authorization (HackerOne/Bugcrowd/VRP scopes, or your own systems). No brute-force, DoS, or exploit delivery.

## Features
- OWASP-lite checks: SQLi error indicators, reflected XSS echo, CSRF indicators, directory traversal hints
- Nmap (optional): embeds `default,vuln,ssl-enum-ciphers` output
- Severity ranking + vector detail + curl repros
- Single-command **Proof Pack** for triagers

## Quick Start
```bash
pip install requests
# optional: install nmap on your system PATH

python vultester_pro.py https://target.tld/path?x=1 --out report.html --evidence-dir evidence --zip-evidence
