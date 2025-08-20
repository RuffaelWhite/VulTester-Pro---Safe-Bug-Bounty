
![Safe](https://img.shields.io/badge/mode-safe-green)
![OWASP](https://img.shields.io/badge/owasp-top10%20lite-blue)
![Evidence](https://img.shields.io/badge/proof-pack-success)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

# VulTesterPro — Safe Bug Bounty Scanner

**Automated, non-destructive vulnerability scanner for bug bounty programs.**

> This tool is designed for **authorized security testing only** (HackerOne/Bugcrowd, VRP scopes, or your own assets). No destructive actions or exploit delivery.

---

## Features

* OWASP-lite checks (safe GET-only probes):

  * SQL Injection error indicators
  * Reflected XSS echo
  * CSRF protection indicators
  * Directory Traversal hints
* Optional Nmap output (`default,vuln,ssl-enum-ciphers`)
* Severity ranking + vector detail + curl repro commands
* Single-command **Proof Pack** for triagers
* Generates HTML report + evidence artifacts (JSON, curl\_repros.txt, summary)

---

## Clickjacking Check (Safe PoC)

### What is Clickjacking?

Clickjacking happens when a site can be embedded in a hidden or transparent iframe, tricking users into clicking unintended elements.

### Safe Proof-of-Concept

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Clickjacking Proof-of-Concept</title>
</head>
<body>
  <h1>Clickjacking Test (Safe PoC)</h1>
  <p>This iframe embeds the target site safely:</p>
  <iframe src="https://cyberzeb.com/" width="800" height="600" style="border:4px solid #2563eb;"></iframe>
  <p>
    If the site loads inside the iframe, it <b>can be framed</b> → vulnerable.  
    If blocked, proper headers prevent framing.
  </p>
</body>
</html>
```

---

## SQL Injection (Safe PoC)

Detects error-based SQLi indicators without modifying data.

```bash
# curl-based safe check
curl -i "https://target.tld/?id=' OR '1'='1"
```

* If database error messages appear (`SQL syntax`, `MySQL`, `SQLite`, etc.), your scanner will log it as a **high severity finding**.

---

## Reflected XSS (Safe PoC)

Checks if input is echoed back in response without executing scripts.

```bash
# curl-based safe check
curl -i "https://target.tld/?q=<script>alert(1)</script>"
```

* If the payload appears in the page **unencoded**, it may be vulnerable (medium severity).

---

## CSRF Protection Check (Safe PoC)

Heuristic check for missing CSRF tokens in forms.

* Sends a **GET request** to target URL and checks for common tokens: `csrf`, `xsrf`, `_token`.
* If none are found, logged as **low severity**.

```bash
curl -i "https://target.tld/path"
```

---

## Directory Traversal (Safe PoC)

Looks for `/etc/passwd` pattern (Linux) without modifying files.

```bash
curl -i "https://target.tld/..%2F..%2F..%2Fetc%2Fpasswd"
```

* If pattern `root:` is found in response → **high severity**.

---

## Quick Start

```bash
pip install requests
# optional: install nmap on PATH

python VulTesterPro.py https://target.tld/path?x=1 --out report.html --evidence-dir evidence --zip-evidence
```

* Generates **HTML report** with safe proof-of-concept artifacts
* **Evidence directory** includes:

  * `http_log.json` — all GET requests
  * `findings.json` — detected issues
  * `curl_repros.txt` — simple commands to reproduce safely
  * `summary.json` — total findings + severity summary

---

## Reporting Example

HTML report shows:

| Severity | Finding                  | Vector                                    | Repro (safe)                                                                        |
| -------- | ------------------------ | ----------------------------------------- | ----------------------------------------------------------------------------------- |
| HIGH     | SQL Injection indicators | param=id payload=' OR '1'='1              | curl -i "[https://target.tld/?id=](https://target.tld/?id=)' OR '1'='1"             |
| MEDIUM   | Reflected XSS            | param=q payload=<script>alert(1)</script> | curl -i "[https://target.tld/?q=](https://target.tld/?q=)<script>alert(1)</script>" |
| LOW      | CSRF indicators missing  | method=GET                                | curl -i "[https://target.tld/](https://target.tld/)"                                |

---

## Disclaimer

* **Legal**: Use only on systems where you have **explicit authorization**.
* **Non-destructive**: No brute-force, DoS, or exploit delivery.
* Authors are **not responsible** for misuse.

---

This README now gives your GitHub repository a **professional, bug-bounty-friendly documentation** showing all safe PoCs, features, and evidence artifacts.
