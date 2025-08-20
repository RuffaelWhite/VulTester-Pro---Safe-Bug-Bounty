#!/usr/bin/env python3
# VulTesterPro — Automated Vulnerability Testing Suite
# For ethical bug bounty & security research ONLY.
# Author: You

import requests
import argparse
import sys
import os
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# --- Colors for output ---
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def banner():
    print(f"""{YELLOW}
====================================
      VulTesterPro v1.0
  Automated Vulnerability Scanner
===================================={RESET}""")

# --- Test Functions ---

def test_sql_injection(url):
    payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "admin'--"]
    vulnerable = []
    for p in payloads:
        try:
            r = requests.get(url, params={"id": p}, timeout=5)
            if any(err in r.text.lower() for err in ["sql", "mysql", "syntax", "odbc", "sqlstate"]):
                vulnerable.append(p)
        except requests.RequestException:
            continue
    return vulnerable

def test_xss(url):
    payloads = ["<script>alert(1)</script>", "\" onmouseover=alert(1) x=\"", "<img src=x onerror=alert(1)>"]
    vulnerable = []
    for p in payloads:
        try:
            r = requests.get(url, params={"q": p}, timeout=5)
            if p in r.text:
                vulnerable.append(p)
        except requests.RequestException:
            continue
    return vulnerable

def test_open_redirect(url):
    payloads = ["//evil.com", "https://evil.com"]
    vulnerable = []
    for p in payloads:
        try:
            r = requests.get(url, params={"next": p}, allow_redirects=False, timeout=5)
            if r.status_code in [301, 302] and "evil.com" in r.headers.get("Location", ""):
                vulnerable.append(p)
        except requests.RequestException:
            continue
    return vulnerable

def test_clickjacking(url):
    try:
        r = requests.get(url, timeout=5)
        if "x-frame-options" not in r.headers and "content-security-policy" not in r.headers:
            return True
    except requests.RequestException:
        pass
    return False

def crawl_links(base_url, limit=10):
    """Very simple crawler"""
    urls = set([base_url])
    try:
        r = requests.get(base_url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            full = urljoin(base_url, a["href"])
            if full.startswith(base_url):
                urls.add(full)
            if len(urls) >= limit:
                break
    except:
        pass
    return list(urls)

# --- Report Writer ---
def save_report(results, target):
    filename = f"report_{target.replace('http://','').replace('https://','').replace('/','_')}.txt"
    with open(filename, "w") as f:
        f.write("==== VulTesterPro Report ====\n")
        f.write(f"Target: {target}\n\n")
        for r in results:
            f.write(f"[#] {r.get('title','Finding')}\n")  # <-- FIXED line
            f.write(f"    Status: {r.get('status')}\n")
            if r.get("payloads"):
                f.write(f"    Payloads: {','.join(r['payloads'])}\n")
            f.write("\n")
    print(f"{GREEN}[+] Report saved to {filename}{RESET}")

# --- Main ---
def main():
    banner()
    parser = argparse.ArgumentParser(description="VulTesterPro - Automated vulnerability tester")
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    args = parser.parse_args()
    target = args.url

    findings = []

    # Crawl a few pages
    urls = crawl_links(target)
    print(f"{YELLOW}[~] Crawling found {len(urls)} pages to test{RESET}")

    for u in urls:
        print(f"{YELLOW}[~] Testing {u}{RESET}")

        sql_res = test_sql_injection(u)
        if sql_res:
            findings.append({"title": "SQL Injection", "status": "VULNERABLE", "payloads": sql_res})
            print(f"{RED}[!] SQL Injection found with payloads: {sql_res}{RESET}")

        xss_res = test_xss(u)
        if xss_res:
            findings.append({"title": "XSS", "status": "VULNERABLE", "payloads": xss_res})
            print(f"{RED}[!] XSS found with payloads: {xss_res}{RESET}")

        redirect_res = test_open_redirect(u)
        if redirect_res:
            findings.append({"title": "Open Redirect", "status": "VULNERABLE", "payloads": redirect_res})
            print(f"{RED}[!] Open Redirect found with payloads: {redirect_res}{RESET}")

        if test_clickjacking(u):
            findings.append({"title": "Clickjacking", "status": "VULNERABLE"})
            print(f"{RED}[!] Clickjacking possible{RESET}")

    if not findings:
        print(f"{GREEN}[+] No obvious vulnerabilities found{RESET}")
    else:
        save_report(findings, target)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
