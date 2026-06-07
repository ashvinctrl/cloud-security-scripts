#!/usr/bin/env python3
"""
secrets_scanner.py — Filesystem Secrets Scanner
================================================
Purpose : Recursively scan files for hardcoded secrets: API keys, passwords,
          connection strings, private keys, and other sensitive patterns.
Usage   : python3 secrets_scanner.py [--path PATH] [--output json|text] [--exclude PATTERN] [--fail-on-findings]
Deps    : Python 3.8+ stdlib only (re, os, sys, pathlib, argparse, json)
"""

import re
import os
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional

# ─── Secret patterns ─────────────────────────────────────────────────────────

PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "severity": "CRITICAL",
        "regex": r"(?<![A-Z0-9])(AKIA|ASIA|AROA)[A-Z0-9]{16}(?![A-Z0-9])",
    },
    {
        "name": "AWS Secret Access Key",
        "severity": "CRITICAL",
        "regex": r"(?i)(aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?",
    },
    {
        "name": "GitHub Personal Access Token",
        "severity": "CRITICAL",
        "regex": r"(?i)gh[pousr]_[A-Za-z0-9]{36,255}",
    },
    {
        "name": "GitHub OAuth Token",
        "severity": "CRITICAL",
        "regex": r"(?i)github_token\s*[=:]\s*['\"]?([a-f0-9]{40})['\"]?",
    },
    {
        "name": "Slack API Token",
        "severity": "HIGH",
        "regex": r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    },
    {
        "name": "Google API Key",
        "severity": "HIGH",
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
    },
    {
        "name": "Stripe Secret Key",
        "severity": "CRITICAL",
        "regex": r"(?i)sk_(live|test)_[0-9a-zA-Z]{24,}",
    },
    {
        "name": "Stripe Publishable Key",
        "severity": "MEDIUM",
        "regex": r"(?i)pk_(live|test)_[0-9a-zA-Z]{24,}",
    },
    {
        "name": "SendGrid API Key",
        "severity": "HIGH",
        "regex": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
    },
    {
        "name": "Twilio Account SID",
        "severity": "HIGH",
        "regex": r"AC[a-f0-9]{32}",
    },
    {
        "name": "RSA / EC Private Key",
        "severity": "CRITICAL",
        "regex": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    },
    {
        "name": "Password Assignment",
        "severity": "HIGH",
        "regex": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
    },
    {
        "name": "Database Connection String",
        "severity": "HIGH",
        "regex": r"(?i)(mysql|postgresql|postgres|mongodb|redis|mssql|oracle)://[^:\s]+:[^@\s]+@",
    },
    {
        "name": "JWT Token",
        "severity": "MEDIUM",
        "regex": r"eyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_.+/=]{10,}",
    },
    {
        "name": "Generic API Key / Secret",
        "severity": "MEDIUM",
        "regex": r"(?i)(api[_\-]?key|api[_\-]?secret|access[_\-]?token|auth[_\-]?token|client[_\-]?secret)\s*[=:]\s*['\"]([A-Za-z0-9\-_]{16,})['\"]",
    },
    {
        "name": "Azure Storage Account Key",
        "severity": "CRITICAL",
        "regex": r"(?i)AccountKey=[A-Za-z0-9+/]{86}==",
    },
    {
        "name": "Azure SAS Token",
        "severity": "HIGH",
        "regex": r"(?i)\bsv=\d{4}-\d{2}-\d{2}&(?:ss|spr|sig)=",
    },
    {
        "name": "GCP Service Account Credential",
        "severity": "CRITICAL",
        "regex": r'"type"\s*:\s*"service_account"',
    },
    {
        "name": "Slack Webhook URL",
        "severity": "HIGH",
        "regex": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    },
    {
        "name": "NPM Auth Token",
        "severity": "HIGH",
        "regex": r"(?i)npm_[A-Za-z0-9]{36}",
    },
    {
        "name": "Docker Hub Token / Password",
        "severity": "HIGH",
        "regex": r"(?i)docker(hub)?[_\-]?(password|token|secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
    },
    {
        "name": "Bearer Token in Header",
        "severity": "MEDIUM",
        "regex": r"(?i)Authorization\s*[=:]\s*['\"]?Bearer\s+([A-Za-z0-9\-_.~+/]+=*)['\"]?",
    },
    {
        "name": "HashiCorp Vault Token",
        "severity": "CRITICAL",
        "regex": r"(?i)(vault[_\-]?token|VAULT_TOKEN)\s*[=:]\s*['\"]?(hvs\.[A-Za-z0-9_\-]{24,}|s\.[A-Za-z0-9]{24,})['\"]?",
    },
]

# ─── Scan scope ──────────────────────────────────────────────────────────────

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php",
    ".java", ".cs", ".sh", ".bash", ".zsh", ".fish",
    ".env", ".cfg", ".conf", ".config",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".xml",
    ".properties", ".tf", ".tfvars", ".hcl",
    ".Dockerfile", ".dockerfile", ".gradle", ".gradle.kts",
    ".md", ".txt", ".csv",
}

ALWAYS_SCAN_NAMES = {".env", ".env.local", ".env.production", ".env.staging"}

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache",
    "dist", "build", ".terraform", ".idea", ".vscode",
    "vendor", "target",
}

MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024  # 1 MB


# ─── Data classes ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    file: str
    line: int
    pattern_name: str
    severity: str
    snippet: str


@dataclass
class ScanResult:
    scanned_files: int = 0
    skipped_files: int = 0
    findings: List[Finding] = field(default_factory=list)

    def summary(self) -> dict:
        by_sev: dict = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "total_findings": len(self.findings),
            "by_severity": by_sev,
        }


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _redact_snippet(line: str, match: re.Match) -> str:
    """Return a redacted context snippet around the match."""
    start, _ = match.span()
    prefix = line[:start][-25:].lstrip()
    return f"...{prefix}[REDACTED]..."


def _should_skip(path: Path) -> bool:
    if path.name in ALWAYS_SCAN_NAMES:
        return False
    if path.suffix and path.suffix not in SCANNABLE_EXTENSIONS:
        return True
    try:
        return path.stat().st_size > MAX_FILE_SIZE_BYTES
    except OSError:
        return True


def _scan_file(path: Path, compiled: list) -> List[Finding]:
    findings: List[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    for lineno, line in enumerate(text.splitlines(), start=1):
        for regex, meta in compiled:
            m = regex.search(line)
            if m:
                findings.append(Finding(
                    file=str(path),
                    line=lineno,
                    pattern_name=meta["name"],
                    severity=meta["severity"],
                    snippet=_redact_snippet(line.rstrip(), m),
                ))
    return findings


# ─── Core scan ───────────────────────────────────────────────────────────────

def scan_directory(root: Path, exclude_re: Optional[re.Pattern] = None) -> ScanResult:
    result = ScanResult()
    compiled = [(re.compile(p["regex"]), p) for p in PATTERNS]

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS
            and not (exclude_re and exclude_re.search(os.path.join(dirpath, d)))
        ]

        for name in filenames:
            fpath = Path(dirpath) / name
            if exclude_re and exclude_re.search(str(fpath)):
                result.skipped_files += 1
                continue
            if _should_skip(fpath):
                result.skipped_files += 1
                continue

            result.scanned_files += 1
            result.findings.extend(_scan_file(fpath, compiled))

    return result


# ─── Output ──────────────────────────────────────────────────────────────────

_SEV_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
}
_RESET = "\033[0m"
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _print_text(result: ScanResult) -> None:
    if not result.findings:
        print("\n\033[92m  No secrets found.\033[0m")
    else:
        sorted_findings = sorted(result.findings, key=lambda f: _SEV_ORDER.get(f.severity, 99))
        print(f"\n{'='*62}")
        print(f"  SECRETS SCANNER  --  {len(result.findings)} finding(s) detected")
        print(f"{'='*62}\n")
        for f in sorted_findings:
            c = _SEV_COLOR.get(f.severity, "")
            print(f"  {c}[{f.severity}]{_RESET}  {f.pattern_name}")
            print(f"    File : {f.file}:{f.line}")
            print(f"    Match: {f.snippet}")
            print()

    s = result.summary()
    print("-- Summary " + "-" * 50)
    print(f"  Files scanned : {s['scanned_files']}")
    print(f"  Files skipped : {s['skipped_files']}")
    print(f"  Total findings: {s['total_findings']}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = s["by_severity"].get(sev, 0)
        if count:
            c = _SEV_COLOR.get(sev, "")
            print(f"    {c}{sev}{_RESET}: {count}")
    print()


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan files for hardcoded secrets and credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 secrets_scanner.py
  python3 secrets_scanner.py --path /path/to/repo --output json
  python3 secrets_scanner.py --exclude "tests/" --fail-on-findings
        """,
    )
    parser.add_argument("--path", "-p", default=".", metavar="DIR",
                        help="Root directory to scan (default: current dir)")
    parser.add_argument("--output", "-o", choices=["text", "json"], default="text",
                        help="Output format")
    parser.add_argument("--exclude", "-e", metavar="REGEX",
                        help="Exclude file/directory paths matching this regex")
    parser.add_argument("--fail-on-findings", "-f", action="store_true",
                        help="Exit with code 1 if findings exist (useful in CI pipelines)")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Error: '{root}' is not a valid directory.", file=sys.stderr)
        return 2

    exclude_re = re.compile(args.exclude) if args.exclude else None

    print(f"Scanning: {root}")
    result = scan_directory(root, exclude_re=exclude_re)

    if args.output == "json":
        print(json.dumps({
            "summary": result.summary(),
            "findings": [asdict(f) for f in result.findings],
        }, indent=2))
    else:
        _print_text(result)

    if args.fail_on_findings and result.findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
