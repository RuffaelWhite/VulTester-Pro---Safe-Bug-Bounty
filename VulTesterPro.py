#!/usr/bin/env python3
# Vul Tester Pro — Automated Vulnerability Scanner (Extended + Proof Pack)
# Safe | All‑in‑One | CLI | Bug‑Bounty Friendly (non‑destructive)
# Author: 0day_csg | License: MIT
"""
LEGAL & SCOPE
- This tool is designed for *authorized* security testing only (bug bounty programs, your own assets,
  or systems where you have explicit written permission). It uses **non‑destructive** checks.
- It does NOT brute force, perform DoS, or deliver exploits. Instead it gathers strong evidence
  ("Proof Pack") to demonstrate risk *without causing harm*.

WHAT'S NEW
- "Proof Pack" generation: HTTP transcript logs, safe PoC vectors, curl repro commands, summary JSON
- Evidence bundle (zip) with HTML report + logs for easy submission to platforms (HackerOne/Bugcrowd)
- Expanded OWASP Lite checks (GET-only): SQLi indicators, Reflected XSS echo, CSRF indicators, Dir traversal hints
- Nmap integration (if installed): default,vuln,ssl-enum-ciphers (parsed into evidence)

USAGE
  python vultester_pro.py https://target.tld --out report.html --evidence-dir evidence --zip-evidence
  python vultester_pro.py http://127.0.0.1:8080 -o report.html

DEPENDENCIES
  pip install requests
  (optional) nmap binary on PATH for NSE output
"""

import argparse
import subprocess
import requests
import os
import json
import time
import zipfile
from urllib.parse import urljoin, urlencode, urlparse, quote
from typing import Dict, Any, List

# -----------------------------
# Utility & Logging
# -----------------------------
START_TS = int(time.time())

class ProofLogger:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.http_log: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        if base_dir:
            os.makedirs(base_dir, exist_ok=True)

    def log_http(self, entry: Dict[str, Any]):
        self.http_log.append(entry)

    def add_finding(self, finding: Dict[str, Any]):
        self.findings.append(finding)

    def save_all(self):
        if not self.base_dir:
            return
        with open(os.path.join(self.base_dir, 'http_log.json'), 'w', encoding='utf-8') as f:
            json.dump(self.http_log, f, indent=2)
        with open(os.path.join(self.base_dir, 'findings.json'), 'w', encoding='utf-8') as f:
            json.dump(self.findings, f, indent=2)
        # quick text repros
        with open(os.path.join(self.base_dir, 'curl_repros.txt'), 'w', encoding='utf-8') as f:
            for fl in self.findings:
                if 'repro' in fl and fl['repro']:
                    f.write(f"[#] {fl.get('title','Finding')}
{fl['repro']}

")
        with open(os.path.join(self.base_dir, 'summary.json'), 'w', encoding='utf-8') as f:
            summary = {
                'generated': START_TS,
                'total_findings': len(self.findings),
                'severities': {s: sum(1 for x in self.findings if x.get('severity')==s)
                               for s in ['critical','high','medium','low','info']}
            }
            json.dump(summary, f, indent=2)

# -----------------------------
# Pretty banner
# -----------------------------

def banner():
    print("""
=================================================
   VulTester Pro — Extended + Proof Pack (SAFE)
=================================================
    """)

# -----------------------------
# Nmap Integration (optional)
# -----------------------------

def run_nmap(target: str) -> str:
    print(f"[+] Running Nmap scan on {target} (if available)...")
    try:
        cmd = ["nmap", "-sV", "--script", "default,vuln,ssl-enum-ciphers", "-oX", "-", target]
        result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=600)
        return result.decode(errors='ignore')
    except Exception:
        return "Nmap not available or failed."

# -----------------------------
# Helpers
# -----------------------------

def make_curl(url: str, headers: Dict[str,str]=None) -> str:
    parts = ["curl", "-i", quote(url, safe=':/?&=%._-')]
    hdrs = headers or {"User-Agent": "VulTesterPro/1.2"}
    for k,v in hdrs.items():
        parts += ["-H", f"{k}: {v}"]
    return " ".join(parts)

# -----------------------------
# OWASP Lite Checks (GET-only, safe)
# -----------------------------

def check_sqli(url: str, PL: ProofLogger):
    payload = "' OR '1'='1"
    test_url = f"{url}{'&' if '?' in url else '?'}id=" + quote(payload)
    try:
        r = requests.get(test_url, timeout=8, allow_redirects=True)
        PL.log_http({
            'check':'SQLi', 'url': test_url, 'status': r.status_code,
            'length': len(r.text), 'headers': dict(r.headers)
        })
        if any(x in r.text.lower() for x in ["sql syntax","sqlite","postgresql","mysql","odbc","sqlstate","ora-"]):
            finding = {
                'title': 'SQL Injection indicators (error-based)',
                'severity': 'high',
                'vector': { 'param': 'id', 'payload': payload, 'method':'GET' },
                'evidence': 'Database error patterns observed in response',
                'repro': make_curl(test_url)
            }
            PL.add_finding(finding)
    except Exception:
        pass

def check_xss(url: str, PL: ProofLogger):
    payload = "<script>alert(1)</script>"
    test_url = f"{url}{'&' if '?' in url else '?'}q=" + quote(payload)
    try:
        r = requests.get(test_url, timeout=8, allow_redirects=True)
        PL.log_http({'check':'XSS','url':test_url,'status':r.status_code,'length':len(r.text)})
        if payload in r.text:
            PL.add_finding({
                'title':'Reflected XSS (echo detected)',
                'severity':'medium',
                'vector':{'param':'q','payload':payload,'method':'GET'},
                'evidence':'Payload echoed unencoded in body',
                'repro': make_curl(test_url)
            })
    except Exception:
        pass

def check_csrf(url: str, PL: ProofLogger):
    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
        PL.log_http({'check':'CSRF','url':url,'status':r.status_code,'length':len(r.text)})
        text_low = r.text.lower()
        if ("csrf" not in text_low) and ("xsrf" not in text_low) and ("_token" not in text_low):
            PL.add_finding({
                'title':'CSRF protection indicators missing (heuristic)',
                'severity':'low',
                'vector':{'method':'GET'},
                'evidence':'No common CSRF tokens found in forms/headers',
                'repro': make_curl(url)
            })
    except Exception:
        pass

def check_traversal(url: str, PL: ProofLogger):
    payload = "..%2F..%2F..%2Fetc%2Fpasswd"
    test_url = url.rstrip('/') + '/' + payload
    try:
        r = requests.get(test_url, timeout=8, allow_redirects=True)
        PL.log_http({'check':'Traversal','url':test_url,'status':r.status_code,'length':len(r.text)})
        if "root:" in r.text:
            PL.add_finding({
                'title':'Directory traversal (evidence of /etc/passwd pattern)',
                'severity':'high',
                'vector':{'path_suffix':payload,'method':'GET'},
                'evidence':'Pattern "root:" detected in response',
                'repro': make_curl(test_url)
            })
    except Exception:
        pass

# -----------------------------
# Runner
# -----------------------------

def run_scans(target_url: str, PL: ProofLogger):
    print("[+] Running OWASP Lite (safe) checks...")
    check_sqli(target_url, PL)
    check_xss(target_url, PL)
    check_csrf(target_url, PL)
    check_traversal(target_url, PL)

# -----------------------------
# Reporting (HTML + Evidence bundle)
# -----------------------------

def generate_report(target: str, PL: ProofLogger, nmap_out: str, out_file: str, evidence_dir: str):
    # HTML
    sev_order = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
    findings = sorted(PL.findings, key=lambda x: sev_order.get(x.get('severity','info'),0), reverse=True)

    def esc(s: Any) -> str:
        return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')

    items = []
    for f in findings:
        items.append(f"""
        <tr>
            <td class='sev {esc(f.get('severity'))}'>{esc(f.get('severity','').upper())}</td>
            <td><b>{esc(f.get('title'))}</b><br><small>{esc(f.get('evidence',''))}</small></td>
            <td><code>{esc(json.dumps(f.get('vector',{})))}</code></td>
            <td><pre>{esc(f.get('repro',''))}</pre></td>
        </tr>
        """)

    html = f"""
<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>VulTester Pro Report</title>
<style>
body{{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#f7f7fb;margin:24px}}
.card{{background:#fff;border-radius:16px;box-shadow:0 8px 24px rgba(0,0,0,.08);padding:16px;margin:12px 0}}
.table{{width:100%;border-collapse:collapse}}
.table th,.table td{{border-bottom:1px solid #eee;padding:8px;vertical-align:top}}
.sev.info{{color:#4b5563}}.sev.low{{color:#2563eb}}.sev.medium{{color:#d97706}}
.sev.high{{color:#dc2626;font-weight:700}}.sev.critical{{color:#7c2d12;font-weight:800}}
pre,code{{background:#f5f5f7;border-radius:8px;padding:8px;display:block;white-space:pre-wrap;word-break:break-all}}
.badge{{display:inline-block;background:#eef2ff;border-radius:999px;padding:2px 8px}}
</style>
</head>
<body>
<div class="card">
  <h1>VulTester Pro — Assessment Report</h1>
  <div>Target: <span class="badge">{esc(target)}</span></div>
  <div>Generated: <span class="badge">{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(START_TS))}</span></div>
</div>
<div class="card">
  <h2>Summary of Findings</h2>
  <table class="table">
    <thead><tr><th>Severity</th><th>Finding</th><th>Vector</th><th>Repro (safe)</th></tr></thead>
    <tbody>
      {''.join(items) if items else '<tr><td colspan="4">No issues detected by safe checks.</td></tr>'}
    </tbody>
  </table>
</div>
<div class="card">
  <h2>Nmap Output (if available)</h2>
  <pre>{esc(nmap_out[:16000])}</pre>
</div>
<div class="card">
  <h2>Artifacts</h2>
  <ul>
    <li>http_log.json</li>
    <li>findings.json</li>
    <li>curl_repros.txt</li>
    <li>summary.json</li>
  </ul>
  <p><small>All artifacts are safe, read‑only evidence. No exploits were executed.</small></p>
</div>
</body>
</html>
"""
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(html)

    # Save evidence JSON files
    PL.save_all()

    # If evidence_dir exists, drop a copy of the HTML there too
    if evidence_dir:
        try:
            os.makedirs(evidence_dir, exist_ok=True)
            base = os.path.join(evidence_dir, 'report.html')
            with open(base, 'w', encoding='utf-8') as f:
                f.write(html)
        except Exception:
            pass

# -----------------------------
# CLI
# -----------------------------

def main():
    banner()
    ap = argparse.ArgumentParser(description="VulTester Pro (Safe) — Extended + Proof Pack")
    ap.add_argument('target', help='Target URL (prefer a specific endpoint) or host')
    ap.add_argument('-o','--out', default='report.html', help='Output HTML report file')
    ap.add_argument('--evidence-dir', default='evidence', help='Directory to store evidence artifacts')
    ap.add_argument('--zip-evidence', action='store_true', help='Zip the evidence directory to evidence.zip')
    args = ap.parse_args()

    ev_dir = args.evidence_dir or ''
    PL = ProofLogger(ev_dir)

    target = args.target
    # Run checks (web-focused; keep to GET-only safe probes)
    run_scans(target, PL)

    # Optional nmap (works with hostnames/IPs)
    nmap_out = run_nmap(urlparse(target).hostname or target)

    # Report + artifacts
    generate_report(target, PL, nmap_out, args.out, ev_dir)

    if args.zip_evidence and ev_dir:
        zip_path = 'evidence.zip'
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(ev_dir):
                for fn in files:
                    full = os.path.join(root, fn)
                    zf.write(full, arcname=os.path.relpath(full, ev_dir))
        print(f"[+] Evidence zipped: {zip_path}")

    print(f"[+] Done. Report: {args.out}  | Evidence dir: {ev_dir}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
# Vul Tester Pro — Automated Vulnerability Scanner (Extended + Proof Pack)
# Safe | All‑in‑One | CLI | Bug‑Bounty Friendly (non‑destructive)
# Author: You + GPT-5 Thinking | License: MIT
"""
LEGAL & SCOPE
- This tool is designed for *authorized* security testing only (bug bounty programs, your own assets,
  or systems where you have explicit written permission). It uses **non‑destructive** checks.
- It does NOT brute force, perform DoS, or deliver exploits. Instead it gathers strong evidence
  ("Proof Pack") to demonstrate risk *without causing harm*.

WHAT'S NEW
- "Proof Pack" generation: HTTP transcript logs, safe PoC vectors, curl repro commands, summary JSON
- Evidence bundle (zip) with HTML report + logs for easy submission to platforms (HackerOne/Bugcrowd)
- Expanded OWASP Lite checks (GET-only): SQLi indicators, Reflected XSS echo, CSRF indicators, Dir traversal hints
- Nmap integration (if installed): default,vuln,ssl-enum-ciphers (parsed into evidence)

USAGE
  python vultester_pro.py https://target.tld --out report.html --evidence-dir evidence --zip-evidence
  python vultester_pro.py http://127.0.0.1:8080 -o report.html

DEPENDENCIES
  pip install requests
  (optional) nmap binary on PATH for NSE output
"""

import argparse
import subprocess
import requests
import os
import json
import time
import zipfile
from urllib.parse import urljoin, urlencode, urlparse, quote
from typing import Dict, Any, List

# -----------------------------
# Utility & Logging
# -----------------------------
START_TS = int(time.time())

class ProofLogger:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.http_log: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        if base_dir:
            os.makedirs(base_dir, exist_ok=True)

    def log_http(self, entry: Dict[str, Any]):
        self.http_log.append(entry)

    def add_finding(self, finding: Dict[str, Any]):
        self.findings.append(finding)

    def save_all(self):
        if not self.base_dir:
            return
        with open(os.path.join(self.base_dir, 'http_log.json'), 'w', encoding='utf-8') as f:
            json.dump(self.http_log, f, indent=2)
        with open(os.path.join(self.base_dir, 'findings.json'), 'w', encoding='utf-8') as f:
            json.dump(self.findings, f, indent=2)
        # quick text repros
        with open(os.path.join(self.base_dir, 'curl_repros.txt'), 'w', encoding='utf-8') as f:
            for fl in self.findings:
                if 'repro' in fl and fl['repro']:
                    f.write(f"[#] {fl.get('title','Finding')}
{fl['repro']}

")
        with open(os.path.join(self.base_dir, 'summary.json'), 'w', encoding='utf-8') as f:
            summary = {
                'generated': START_TS,
                'total_findings': len(self.findings),
                'severities': {s: sum(1 for x in self.findings if x.get('severity')==s)
                               for s in ['critical','high','medium','low','info']}
            }
            json.dump(summary, f, indent=2)

# -----------------------------
# Pretty banner
# -----------------------------

def banner():
    print("""
=================================================
   VulTester Pro — Extended + Proof Pack (SAFE)
=================================================
    """)

# -----------------------------
# Nmap Integration (optional)
# -----------------------------

def run_nmap(target: str) -> str:
    print(f"[+] Running Nmap scan on {target} (if available)...")
    try:
        cmd = ["nmap", "-sV", "--script", "default,vuln,ssl-enum-ciphers", "-oX", "-", target]
        result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=600)
        return result.decode(errors='ignore')
    except Exception:
        return "Nmap not available or failed."

# -----------------------------
# Helpers
# -----------------------------

def make_curl(url: str, headers: Dict[str,str]=None) -> str:
    parts = ["curl", "-i", quote(url, safe=':/?&=%._-')]
    hdrs = headers or {"User-Agent": "VulTesterPro/1.2"}
    for k,v in hdrs.items():
        parts += ["-H", f"{k}: {v}"]
    return " ".join(parts)

# -----------------------------
# OWASP Lite Checks (GET-only, safe)
# -----------------------------

def check_sqli(url: str, PL: ProofLogger):
    payload = "' OR '1'='1"
    test_url = f"{url}{'&' if '?' in url else '?'}id=" + quote(payload)
    try:
        r = requests.get(test_url, timeout=8, allow_redirects=True)
        PL.log_http({
            'check':'SQLi', 'url': test_url, 'status': r.status_code,
            'length': len(r.text), 'headers': dict(r.headers)
        })
        if any(x in r.text.lower() for x in ["sql syntax","sqlite","postgresql","mysql","odbc","sqlstate","ora-"]):
            finding = {
                'title': 'SQL Injection indicators (error-based)',
                'severity': 'high',
                'vector': { 'param': 'id', 'payload': payload, 'method':'GET' },
                'evidence': 'Database error patterns observed in response',
                'repro': make_curl(test_url)
            }
            PL.add_finding(finding)
    except Exception:
        pass

def check_xss(url: str, PL: ProofLogger):
    payload = "<script>alert(1)</script>"
    test_url = f"{url}{'&' if '?' in url else '?'}q=" + quote(payload)
    try:
        r = requests.get(test_url, timeout=8, allow_redirects=True)
        PL.log_http({'check':'XSS','url':test_url,'status':r.status_code,'length':len(r.text)})
        if payload in r.text:
            PL.add_finding({
                'title':'Reflected XSS (echo detected)',
                'severity':'medium',
                'vector':{'param':'q','payload':payload,'method':'GET'},
                'evidence':'Payload echoed unencoded in body',
                'repro': make_curl(test_url)
            })
    except Exception:
        pass

def check_csrf(url: str, PL: ProofLogger):
    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
        PL.log_http({'check':'CSRF','url':url,'status':r.status_code,'length':len(r.text)})
        text_low = r.text.lower()
        if ("csrf" not in text_low) and ("xsrf" not in text_low) and ("_token" not in text_low):
            PL.add_finding({
                'title':'CSRF protection indicators missing (heuristic)',
                'severity':'low',
                'vector':{'method':'GET'},
                'evidence':'No common CSRF tokens found in forms/headers',
                'repro': make_curl(url)
            })
    except Exception:
        pass

def check_traversal(url: str, PL: ProofLogger):
    payload = "..%2F..%2F..%2Fetc%2Fpasswd"
    test_url = url.rstrip('/') + '/' + payload
    try:
        r = requests.get(test_url, timeout=8, allow_redirects=True)
        PL.log_http({'check':'Traversal','url':test_url,'status':r.status_code,'length':len(r.text)})
        if "root:" in r.text:
            PL.add_finding({
                'title':'Directory traversal (evidence of /etc/passwd pattern)',
                'severity':'high',
                'vector':{'path_suffix':payload,'method':'GET'},
                'evidence':'Pattern "root:" detected in response',
                'repro': make_curl(test_url)
            })
    except Exception:
        pass

# -----------------------------
# Runner
# -----------------------------

def run_scans(target_url: str, PL: ProofLogger):
    print("[+] Running OWASP Lite (safe) checks...")
    check_sqli(target_url, PL)
    check_xss(target_url, PL)
    check_csrf(target_url, PL)
    check_traversal(target_url, PL)

# -----------------------------
# Reporting (HTML + Evidence bundle)
# -----------------------------

def generate_report(target: str, PL: ProofLogger, nmap_out: str, out_file: str, evidence_dir: str):
    # HTML
    sev_order = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
    findings = sorted(PL.findings, key=lambda x: sev_order.get(x.get('severity','info'),0), reverse=True)

    def esc(s: Any) -> str:
        return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')

    items = []
    for f in findings:
        items.append(f"""
        <tr>
            <td class='sev {esc(f.get('severity'))}'>{esc(f.get('severity','').upper())}</td>
            <td><b>{esc(f.get('title'))}</b><br><small>{esc(f.get('evidence',''))}</small></td>
            <td><code>{esc(json.dumps(f.get('vector',{})))}</code></td>
            <td><pre>{esc(f.get('repro',''))}</pre></td>
        </tr>
        """)

    html = f"""
<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>VulTester Pro Report</title>
<style>
body{{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;background:#f7f7fb;margin:24px}}
.card{{background:#fff;border-radius:16px;box-shadow:0 8px 24px rgba(0,0,0,.08);padding:16px;margin:12px 0}}
.table{{width:100%;border-collapse:collapse}}
.table th,.table td{{border-bottom:1px solid #eee;padding:8px;vertical-align:top}}
.sev.info{{color:#4b5563}}.sev.low{{color:#2563eb}}.sev.medium{{color:#d97706}}
.sev.high{{color:#dc2626;font-weight:700}}.sev.critical{{color:#7c2d12;font-weight:800}}
pre,code{{background:#f5f5f7;border-radius:8px;padding:8px;display:block;white-space:pre-wrap;word-break:break-all}}
.badge{{display:inline-block;background:#eef2ff;border-radius:999px;padding:2px 8px}}
</style>
</head>
<body>
<div class="card">
  <h1>VulTester Pro — Assessment Report</h1>
  <div>Target: <span class="badge">{esc(target)}</span></div>
  <div>Generated: <span class="badge">{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(START_TS))}</span></div>
</div>
<div class="card">
  <h2>Summary of Findings</h2>
  <table class="table">
    <thead><tr><th>Severity</th><th>Finding</th><th>Vector</th><th>Repro (safe)</th></tr></thead>
    <tbody>
      {''.join(items) if items else '<tr><td colspan="4">No issues detected by safe checks.</td></tr>'}
    </tbody>
  </table>
</div>
<div class="card">
  <h2>Nmap Output (if available)</h2>
  <pre>{esc(nmap_out[:16000])}</pre>
</div>
<div class="card">
  <h2>Artifacts</h2>
  <ul>
    <li>http_log.json</li>
    <li>findings.json</li>
    <li>curl_repros.txt</li>
    <li>summary.json</li>
  </ul>
  <p><small>All artifacts are safe, read‑only evidence. No exploits were executed.</small></p>
</div>
</body>
</html>
"""
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(html)

    # Save evidence JSON files
    PL.save_all()

    # If evidence_dir exists, drop a copy of the HTML there too
    if evidence_dir:
        try:
            os.makedirs(evidence_dir, exist_ok=True)
            base = os.path.join(evidence_dir, 'report.html')
            with open(base, 'w', encoding='utf-8') as f:
                f.write(html)
        except Exception:
            pass

# -----------------------------
# CLI
# -----------------------------

def main():
    banner()
    ap = argparse.ArgumentParser(description="VulTester Pro (Safe) — Extended + Proof Pack")
    ap.add_argument('target', help='Target URL (prefer a specific endpoint) or host')
    ap.add_argument('-o','--out', default='report.html', help='Output HTML report file')
    ap.add_argument('--evidence-dir', default='evidence', help='Directory to store evidence artifacts')
    ap.add_argument('--zip-evidence', action='store_true', help='Zip the evidence directory to evidence.zip')
    args = ap.parse_args()

    ev_dir = args.evidence_dir or ''
    PL = ProofLogger(ev_dir)

    target = args.target
    # Run checks (web-focused; keep to GET-only safe probes)
    run_scans(target, PL)

    # Optional nmap (works with hostnames/IPs)
    nmap_out = run_nmap(urlparse(target).hostname or target)

    # Report + artifacts
    generate_report(target, PL, nmap_out, args.out, ev_dir)

    if args.zip_evidence and ev_dir:
        zip_path = 'evidence.zip'
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(ev_dir):
                for fn in files:
                    full = os.path.join(root, fn)
                    zf.write(full, arcname=os.path.relpath(full, ev_dir))
        print(f"[+] Evidence zipped: {zip_path}")

    print(f"[+] Done. Report: {args.out}  | Evidence dir: {ev_dir}")

if __name__ == "__main__":
    main()
