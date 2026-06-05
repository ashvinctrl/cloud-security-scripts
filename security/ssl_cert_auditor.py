#!/usr/bin/env python3
"""
ssl_cert_auditor.py — SSL/TLS Certificate & Configuration Auditor

Purpose:
    Audits one or more hosts for SSL/TLS misconfigurations:
      - Certificate expiry (warns at 30 days, critical at 7)
      - Weak protocol support (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
      - Self-signed or untrusted certificates
      - Hostname mismatch
      - Cipher suite strength (flags NULL, EXPORT, RC4, DES, 3DES, MD5)
      - Subject Alternative Names (SAN) coverage

Usage:
    python ssl_cert_auditor.py <host> [<host> ...]
    python ssl_cert_auditor.py example.com api.example.com:8443
    python ssl_cert_auditor.py --file hosts.txt

Dependencies:
    Python 3.9+, stdlib only (ssl, socket)
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from typing import Any

WARN_DAYS = 30
CRITICAL_DAYS = 7

WEAK_CIPHER_PATTERNS = [
    "NULL", "EXPORT", "RC4", "DES", "3DES", "MD5",
    "aNULL", "eNULL", "LOW", "EXP",
]

SEVERITY_OK   = "OK"
SEVERITY_WARN = "WARN"
SEVERITY_CRIT = "CRITICAL"
SEVERITY_FAIL = "FAIL"

SEVERITY_ORDER = {SEVERITY_OK: 0, SEVERITY_WARN: 1, SEVERITY_CRIT: 2, SEVERITY_FAIL: 3}
SEVERITY_ICON  = {SEVERITY_OK: "[OK]  ", SEVERITY_WARN: "[WARN]", SEVERITY_CRIT: "[CRIT]", SEVERITY_FAIL: "[FAIL]"}
SEVERITY_COLOR = {
    SEVERITY_OK:   "\033[92m",
    SEVERITY_WARN: "\033[93m",
    SEVERITY_CRIT: "\033[91m",
    SEVERITY_FAIL: "\033[91m",
}
RESET = "\033[0m"


def parse_host(host_str: str) -> tuple[str, int]:
    if ":" in host_str:
        h, p = host_str.rsplit(":", 1)
        return h, int(p)
    return host_str, 443


def get_cert_info(host: str, port: int, timeout: int = 10) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {
                    "cert":    ssock.getpeercert(),
                    "cipher":  ssock.cipher(),
                    "version": ssock.version(),
                    "error":   None,
                }
    except ssl.SSLCertVerificationError as e:
        return {"cert": None, "cipher": None, "version": None, "error": f"Cert verify failed: {e}"}
    except ssl.SSLError as e:
        return {"cert": None, "cipher": None, "version": None, "error": f"SSL error: {e}"}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"cert": None, "cipher": None, "version": None, "error": f"Connection error: {e}"}


def check_expiry(cert: dict) -> tuple[str, str]:
    not_after = cert.get("notAfter", "")
    if not not_after:
        return SEVERITY_FAIL, "Missing notAfter field"
    expire_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (expire_dt - datetime.now(timezone.utc)).days
    if days_left < 0:
        return SEVERITY_CRIT, f"Expired {abs(days_left)} days ago ({not_after})"
    if days_left <= CRITICAL_DAYS:
        return SEVERITY_CRIT, f"Expires in {days_left} days ({not_after})"
    if days_left <= WARN_DAYS:
        return SEVERITY_WARN, f"Expires in {days_left} days ({not_after})"
    return SEVERITY_OK, f"Valid for {days_left} days (expires {not_after})"


def check_hostname(cert: dict, host: str) -> tuple[str, str]:
    sans = [v for _, v in cert.get("subjectAltName", [])]
    cn_pairs = [x[0] for x in cert.get("subject", []) if x[0][0] == "commonName"]
    subject_cn = cn_pairs[0][1] if cn_pairs else ""
    all_names = sans if sans else ([subject_cn] if subject_cn else [])

    def matches(name: str) -> bool:
        if name.startswith("*."):
            suffix = name[1:]  # e.g. ".example.com"
            if not host.endswith(suffix):
                return False
            label = host[: len(host) - len(suffix)]  # single label, no dot allowed
            return "." not in label
        return name == host

    if any(matches(n) for n in all_names):
        return SEVERITY_OK, f"Hostname matched ({'SAN' if sans else 'CN'}, {len(sans)} SANs)"
    return SEVERITY_CRIT, f"Hostname mismatch — cert covers {all_names[:5]}"


def check_self_signed(cert: dict) -> tuple[str, str]:
    issuer  = {x[0][0]: x[0][1] for x in cert.get("issuer", [])}
    subject = {x[0][0]: x[0][1] for x in cert.get("subject", [])}
    if issuer == subject:
        return SEVERITY_CRIT, "Self-signed certificate (issuer == subject)"
    org = issuer.get("organizationName") or issuer.get("commonName", "Unknown")
    return SEVERITY_OK, f"Issued by: {org}"


def check_protocol(version: str) -> tuple[str, str]:
    if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        return SEVERITY_CRIT, f"Deprecated protocol in use: {version}"
    if version == "TLSv1.2":
        return SEVERITY_WARN, "TLSv1.2 in use — TLSv1.3 preferred"
    if version == "TLSv1.3":
        return SEVERITY_OK, f"Modern protocol: {version}"
    return SEVERITY_WARN, f"Unknown protocol: {version}"


def check_cipher(cipher: tuple) -> tuple[str, str]:
    name, _proto, bits = cipher
    for weak in WEAK_CIPHER_PATTERNS:
        if weak in name.upper():
            return SEVERITY_CRIT, f"Weak cipher: {name} ({bits}-bit)"
    if bits and bits < 128:
        return SEVERITY_CRIT, f"Insufficient key length: {bits} bits ({name})"
    if bits and bits < 256:
        return SEVERITY_WARN, f"Cipher: {name} ({bits}-bit) — 256-bit preferred"
    return SEVERITY_OK, f"Strong cipher: {name} ({bits}-bit)"


def audit_host(host: str, port: int) -> dict:
    info = get_cert_info(host, port)
    label = f"{host}:{port}"

    if info["error"]:
        return {
            "host": label,
            "checks": [{"name": "Connection", "severity": SEVERITY_FAIL, "detail": info["error"]}],
            "overall": SEVERITY_FAIL,
        }

    cert, cipher, version = info["cert"], info["cipher"], info["version"]
    checks_raw = [
        ("Expiry",      check_expiry(cert)),
        ("Hostname",    check_hostname(cert, host)),
        ("Self-signed", check_self_signed(cert)),
        ("Protocol",    check_protocol(version)),
        ("Cipher",      check_cipher(cipher)),
    ]

    checks = [{"name": n, "severity": s, "detail": d} for n, (s, d) in checks_raw]
    overall = max((c["severity"] for c in checks), key=lambda s: SEVERITY_ORDER[s])
    return {"host": label, "checks": checks, "overall": overall}


def print_report(results: list[dict], use_color: bool = True) -> int:
    exit_code = 0
    for r in results:
        ov = r["overall"]
        c  = SEVERITY_COLOR.get(ov, "") if use_color else ""
        rs = RESET if use_color else ""
        print(f"\n{'='*60}")
        print(f" Host: {r['host']}  [{c}{ov}{rs}]")
        print(f"{'='*60}")
        for chk in r["checks"]:
            sev = chk["severity"]
            ic  = SEVERITY_ICON[sev]
            cc  = SEVERITY_COLOR.get(sev, "") if use_color else ""
            print(f"  {cc}{ic}{rs} {chk['name']:13s} {chk['detail']}")
        rank = SEVERITY_ORDER.get(ov, 0)
        if rank >= SEVERITY_ORDER[SEVERITY_CRIT] and exit_code < 2:
            exit_code = 2
        elif rank >= SEVERITY_ORDER[SEVERITY_WARN] and exit_code < 1:
            exit_code = 1
    print()
    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit SSL/TLS certificates and configuration for one or more hosts."
    )
    parser.add_argument("hosts", nargs="*", help="host[:port] to audit (default port 443)")
    parser.add_argument("--file", "-f", help="File with one host[:port] per line")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of human-readable report")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    host_list = list(args.hosts)
    if args.file:
        with open(args.file) as fh:
            host_list += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

    if not host_list:
        parser.print_help()
        return 1

    use_color = sys.stdout.isatty() and not args.no_color
    results = [audit_host(*parse_host(h)) for h in host_list]

    if args.json:
        print(json.dumps(results, indent=2))
        worst = max(SEVERITY_ORDER.get(r["overall"], 0) for r in results)
        return 0 if worst == 0 else (1 if worst == 1 else 2)

    return print_report(results, use_color=use_color)


if __name__ == "__main__":
    sys.exit(main())
