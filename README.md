# VulTester Pro — Safe Bug-Bounty Scanner + Proof Pack

**Non-destructive evidence builder for bug-bounty and VRP workflows.**  
Runs OWASP Top-10 lite probes (GET-only) and captures a clean **Proof Pack**:
- `report.html` (ranked findings, vectors, safe curl repros)
- `http_log.json` (HTTP transcript)
- `findings.json` (structured issues)
- `curl_repros.txt` (copy-paste repros)
- `summary.json`
- optional `evidence.zip`

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
