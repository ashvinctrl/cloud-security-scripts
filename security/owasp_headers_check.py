#!/usr/bin/env python3
"""
owasp_headers_check.py - OWASP HTTP Security Headers Auditor

Purpose:
    Checks one or more URLs for the presence and correctness of OWASP-recommended
    HTTP security headers. Flags missing, misconfigured, or insecure header values
    and prints a color-coded report with remediation guidance.

Usage:
    python3 owasp_headers_check.py <url> [url ...]
    python3 owasp_headers_check.py --file urls.txt
    python3 owasp_headers_check.py https://example.com --json

Dependencies:
    pip install requests

Headers checked (OWASP Security Headers Project):
    Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options,
    X-Frame-Options, Referrer-Policy, Permissions-Policy,
    X-XSS-Protection (deprecated but flagged if unsafe), Server (version leak)
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Optional

import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ANSI colours — disabled when output is piped
USE_COLOR = sys.stdout.isatty()
RED    = "\033[91m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
GREEN  = "\033[92m" if USE_COLOR else ""
CYAN   = "\033[96m" if USE_COLOR else ""
BOLD   = "\033[1m"  if USE_COLOR else ""
RESET  = "\033[0m"  if USE_COLOR else ""

STATUS_COLOR  = {"PASS": GREEN, "WARN": YELLOW, "FAIL": RED, "INFO": CYAN}
STATUS_SYMBOL = {"PASS": "v", "WARN": "!", "FAIL": "x", "INFO": "i"}


@dataclass
class CheckResult:
    header: str
    status: str          # PASS | WARN | FAIL | INFO
    value: Optional[str]
    message: str
    fix: str


# ── Individual header checks ─────────────────────────────────────────────────

def check_hsts(headers: dict) -> CheckResult:
    h = "Strict-Transport-Security"
    val = headers.get(h)
    if not val:
        return CheckResult(h, "FAIL", None, "Header missing",
                           "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
    lower = val.lower()
    age = 0
    for part in lower.split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                age = int(part.split("=", 1)[1])
            except ValueError:
                pass
    if age < 31536000:
        return CheckResult(h, "WARN", val,
                           f"max-age={age} is below recommended 31536000 (1 year)",
                           "Increase max-age to at least 31536000")
    if "includesubdomains" not in lower:
        return CheckResult(h, "WARN", val, "includeSubDomains directive missing",
                           "Add includeSubDomains to cover all subdomains")
    return CheckResult(h, "PASS", val, "Configured correctly", "")


def check_csp(headers: dict) -> CheckResult:
    h = "Content-Security-Policy"
    val = headers.get(h)
    if not val:
        return CheckResult(h, "FAIL", None, "Header missing — XSS mitigations absent",
                           "Add a restrictive CSP, e.g.: default-src 'self'; script-src 'self'")
    lower = val.lower()
    issues = []
    if "'unsafe-inline'" in lower:
        issues.append("'unsafe-inline' allows inline scripts/styles")
    if "'unsafe-eval'" in lower:
        issues.append("'unsafe-eval' allows eval() — high XSS risk")
    if re.search(r"(default|script)-src\s+\*", lower):
        issues.append("Wildcard (*) source in default-src or script-src is overly permissive")
    if issues:
        return CheckResult(h, "WARN", val, "; ".join(issues),
                           "Remove 'unsafe-inline', 'unsafe-eval', and wildcard sources")
    return CheckResult(h, "PASS", val, "No obvious misconfigurations detected", "")


def check_xcto(headers: dict) -> CheckResult:
    h = "X-Content-Type-Options"
    val = headers.get(h)
    if not val:
        return CheckResult(h, "FAIL", None, "Header missing — MIME sniffing enabled",
                           "Add: X-Content-Type-Options: nosniff")
    if val.strip().lower() != "nosniff":
        return CheckResult(h, "WARN", val, f"Unexpected value '{val}' (expected 'nosniff')",
                           "Set value to exactly: nosniff")
    return CheckResult(h, "PASS", val, "Configured correctly", "")


def check_xfo(headers: dict) -> CheckResult:
    h = "X-Frame-Options"
    val = headers.get(h)
    csp = headers.get("Content-Security-Policy", "")
    if "frame-ancestors" in csp.lower():
        return CheckResult(h, "PASS", val or "(controlled by CSP frame-ancestors)",
                           "Clickjacking protection via CSP frame-ancestors", "")
    if not val:
        return CheckResult(h, "FAIL", None, "Header missing — clickjacking possible",
                           "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors)")
    upper = val.strip().upper()
    if upper not in ("DENY", "SAMEORIGIN"):
        return CheckResult(h, "WARN", val, f"Value '{val}' is non-standard",
                           "Use DENY or SAMEORIGIN")
    return CheckResult(h, "PASS", val, "Configured correctly", "")


def check_referrer(headers: dict) -> CheckResult:
    h = "Referrer-Policy"
    val = headers.get(h)
    safe = {
        "no-referrer", "no-referrer-when-downgrade", "strict-origin",
        "strict-origin-when-cross-origin", "same-origin",
    }
    if not val:
        return CheckResult(h, "WARN", None, "Header missing — browser default leaks full URL",
                           "Add: Referrer-Policy: strict-origin-when-cross-origin")
    if val.strip().lower() not in safe:
        return CheckResult(h, "WARN", val, f"Value '{val}' may leak sensitive URL data",
                           "Use: strict-origin-when-cross-origin or no-referrer")
    return CheckResult(h, "PASS", val, "Configured correctly", "")


def check_permissions(headers: dict) -> CheckResult:
    h = "Permissions-Policy"
    val = headers.get(h) or headers.get("Feature-Policy")
    if not val:
        return CheckResult(h, "WARN", None, "Header missing — browser features unrestricted",
                           "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()")
    return CheckResult(h, "PASS", val, "Header present (review individual directives manually)", "")


def check_xxss(headers: dict) -> CheckResult:
    """X-XSS-Protection is deprecated; value '1' alone is risky."""
    h = "X-XSS-Protection"
    val = headers.get(h)
    if not val:
        return CheckResult(h, "INFO", None,
                           "Header absent — deprecated, rely on CSP instead", "")
    stripped = val.strip().lower()
    if stripped == "0":
        return CheckResult(h, "INFO", val, "Explicitly disabled (acceptable when CSP is set)", "")
    if stripped == "1":
        return CheckResult(h, "WARN", val,
                           "Value '1' without mode=block can introduce reflected XSS",
                           "Use '0' (rely on CSP) or '1; mode=block'")
    return CheckResult(h, "INFO", val, "Header present (deprecated — prefer CSP)", "")


def check_server(headers: dict) -> CheckResult:
    """Server header leaks version info."""
    h = "Server"
    val = headers.get(h)
    if not val:
        return CheckResult(h, "PASS", None, "Server header absent — good", "")
    if re.search(r"[\d.]{3,}", val):
        return CheckResult(h, "WARN", val, "Server header exposes version information",
                           "Strip version token from Server header in web server config")
    return CheckResult(h, "INFO", val, "Server header present but no version string detected", "")


CHECKS = [
    check_hsts,
    check_csp,
    check_xcto,
    check_xfo,
    check_referrer,
    check_permissions,
    check_xxss,
    check_server,
]


# ── Audit a single URL ────────────────────────────────────────────────────────

def audit_url(url: str, timeout: int = 10) -> list:
    try:
        resp = requests.get(
            url, timeout=timeout, verify=False, allow_redirects=True,
            headers={"User-Agent": "owasp-headers-check/1.0"},
        )
        raw_headers = dict(resp.headers)
    except requests.RequestException as exc:
        print(f"{RED}ERROR{RESET} Could not reach {url}: {exc}")
        return []
    return [check(raw_headers) for check in CHECKS]


# ── Reporting ─────────────────────────────────────────────────────────────────

def print_report(url: str, results: list) -> dict:
    print(f"\n{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}  URL: {url}{RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}")

    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "INFO": 0}
    for r in results:
        color  = STATUS_COLOR.get(r.status, "")
        symbol = STATUS_SYMBOL.get(r.status, "?")
        badge  = f"{color}[{symbol} {r.status:<4}]{RESET}"
        print(f"  {badge}  {BOLD}{r.header}{RESET}")
        if r.value:
            short = r.value if len(r.value) <= 80 else r.value[:77] + "..."
            print(f"           Value  : {short}")
        print(f"           Detail : {r.message}")
        if r.fix:
            print(f"           Fix   : {YELLOW}{r.fix}{RESET}")
        counts[r.status] += 1

    total = len(results)
    grade = (
        "A" if counts["FAIL"] == 0 and counts["WARN"] <= 1 else
        "B" if counts["FAIL"] == 0 else
        "C" if counts["FAIL"] == 1 else
        "F"
    )
    grade_color = GREEN if grade == "A" else YELLOW if grade == "B" else RED
    print(f"\n  {'─'*68}")
    print(f"  Checked {total} headers  |  "
          f"{GREEN}PASS:{counts['PASS']}{RESET}  "
          f"{YELLOW}WARN:{counts['WARN']}{RESET}  "
          f"{RED}FAIL:{counts['FAIL']}{RESET}  "
          f"{CYAN}INFO:{counts['INFO']}{RESET}  |  "
          f"Grade: {grade_color}{BOLD}{grade}{RESET}")
    return {"url": url, "counts": counts, "grade": grade,
            "results": [vars(r) for r in results]}


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OWASP HTTP Security Headers Auditor — check security header posture",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("urls", nargs="*", metavar="URL", help="URLs to audit")
    parser.add_argument("--file", "-f", metavar="FILE",
                        help="Text file with one URL per line")
    parser.add_argument("--json", action="store_true",
                        help="Also dump full results as JSON at the end")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    targets = list(args.urls)
    if args.file:
        try:
            with open(args.file) as fh:
                targets.extend(line.strip() for line in fh if line.strip())
        except OSError as exc:
            sys.exit(f"Cannot read URL file: {exc}")

    if not targets:
        parser.print_help()
        sys.exit(1)

    all_reports = []
    for url in targets:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        results = audit_url(url, args.timeout)
        if results:
            report = print_report(url, results)
            all_reports.append(report)

    if args.json and all_reports:
        print("\n" + json.dumps(all_reports, indent=2))


if __name__ == "__main__":
    main()
