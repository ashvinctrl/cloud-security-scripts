#!/usr/bin/env python3
"""
Dockerfile Security Scanner
Purpose : Static analysis of Dockerfiles for security misconfigs and best-practice violations
Usage   : python dockerfile_security_scanner.py [path/to/Dockerfile]
          Exits 0 if only LOW/INFO findings; exits 1 if any CRITICAL or HIGH findings.
Deps    : Python 3.8+ stdlib only — no pip install needed
"""

import sys
import re
import os
from dataclasses import dataclass
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    rule: str
    message: str
    line: int
    fix: str

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ---------------------------------------------------------------------------
# Parser — handles line continuations
# ---------------------------------------------------------------------------

def parse_dockerfile(path: str) -> List[Tuple[int, str]]:
    """Return list of (start_line, full_instruction) with continuations joined."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.readlines()

    instructions: List[Tuple[int, str]] = []
    buf = ""
    start = 0
    for i, line in enumerate(raw, 1):
        stripped = line.rstrip("\n")
        if not buf:
            start = i
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
        else:
            buf += stripped
            full = buf.strip()
            if full and not full.startswith("#"):
                instructions.append((start, full))
            buf = ""
    if buf.strip() and not buf.strip().startswith("#"):
        instructions.append((start, buf.strip()))
    return instructions

# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    (r"(?i)(password|passwd|pwd)\s*=\s*[\"']?\S+",       "hardcoded password"),
    (r"(?i)(api_key|apikey|api[-_]secret)\s*=\s*\S+",    "hardcoded API key"),
    (r"(?i)(secret|token)\s*=\s*[\"']?\S+",              "hardcoded secret/token"),
    (r"(?i)aws_access_key_id\s*=\s*\S+",                 "hardcoded AWS access key"),
    (r"(?i)aws_secret_access_key\s*=\s*\S+",             "hardcoded AWS secret key"),
    (r"GITHUB_TOKEN\s*=\s*[\"']?\S+",                    "hardcoded GitHub token"),
]


def _check_user(instrs: List[Tuple[int, str]]) -> List[Finding]:
    findings = []
    user_lines = [(n, i) for n, i in instrs if i.upper().startswith("USER")]
    if not user_lines:
        findings.append(Finding(
            "HIGH", "NO_USER_INSTRUCTION",
            "No USER instruction — container runs as root by default.",
            0, "Add 'USER nonroot' before CMD/ENTRYPOINT."
        ))
    else:
        lineno, last_instr = user_lines[-1]
        val = last_instr.split(None, 1)[1].strip().lower() if len(last_instr.split()) > 1 else ""
        if val in ("root", "0"):
            findings.append(Finding(
                "HIGH", "USER_IS_ROOT",
                f"Final USER is root (line {lineno}).",
                lineno, "Switch to a non-privileged user in the final stage."
            ))
    return findings


def _check_base_images(instrs: List[Tuple[int, str]]) -> List[Finding]:
    findings = []
    for lineno, instr in instrs:
        if not instr.upper().startswith("FROM"):
            continue
        # strip AS alias
        image = instr.split(None, 1)[1].strip().split()[0]
        if image.upper() == "SCRATCH":
            continue  # scratch is intentionally minimal
        if ":" not in image or image.endswith(":latest"):
            findings.append(Finding(
                "MEDIUM", "UNPINNED_BASE_IMAGE",
                f"Base image '{image}' is not pinned to a version tag or digest (line {lineno}).",
                lineno, "Use a specific tag (e.g. python:3.12-slim) or @sha256 digest."
            ))
    return findings


def _check_add(instrs: List[Tuple[int, str]]) -> List[Finding]:
    findings = []
    for lineno, instr in instrs:
        if instr.upper().startswith("ADD "):
            findings.append(Finding(
                "LOW", "ADD_INSTEAD_OF_COPY",
                f"ADD used at line {lineno} — prefer COPY unless you need URL fetch or tar extraction.",
                lineno, "Replace ADD with COPY for plain file copies to avoid unexpected behavior."
            ))
    return findings


def _check_secrets(instrs: List[Tuple[int, str]]) -> List[Finding]:
    findings = []
    for lineno, instr in instrs:
        keyword = instr.split()[0].upper() if instr.split() else ""
        if keyword not in ("ENV", "ARG"):
            continue
        for pattern, label in _SECRET_PATTERNS:
            if re.search(pattern, instr):
                findings.append(Finding(
                    "CRITICAL", "HARDCODED_SECRET",
                    f"Possible {label} in {keyword} at line {lineno}.",
                    lineno, "Use runtime env vars or Docker secrets — never bake credentials into the image."
                ))
    return findings


def _check_run(instrs: List[Tuple[int, str]]) -> List[Finding]:
    findings = []
    for lineno, instr in instrs:
        if not instr.upper().startswith("RUN "):
            continue
        cmd = instr[4:]

        if re.search(r"(curl|wget).+\|\s*(ba)?sh", cmd):
            findings.append(Finding(
                "HIGH", "CURL_PIPE_BASH",
                f"'curl/wget | bash' pattern at line {lineno} — blindly executes remote code.",
                lineno, "Download first, verify checksum, then execute in separate steps."
            ))

        if "--privileged" in cmd:
            findings.append(Finding(
                "CRITICAL", "PRIVILEGED_FLAG",
                f"RUN uses --privileged at line {lineno}.",
                lineno, "Remove --privileged; grant only the specific capabilities needed."
            ))

        if re.search(r"\brm\s+-rf\s+/", cmd):
            findings.append(Finding(
                "HIGH", "DESTRUCTIVE_RM",
                f"'rm -rf /' pattern detected at line {lineno}.",
                lineno, "Scope deletions to specific directories, never root."
            ))

        if re.search(r"(apt-get install|yum install|apk add)\s+\w", cmd):
            if not re.search(r"(apt-get install|yum install|apk add).*=", cmd):
                findings.append(Finding(
                    "LOW", "UNPINNED_PACKAGE",
                    f"Package install without version pinning at line {lineno}.",
                    lineno, "Pin versions for reproducible builds: apt-get install nginx=1.25.*"
                ))

    return findings


def _check_expose(instrs: List[Tuple[int, str]]) -> List[Finding]:
    findings = []
    for lineno, instr in instrs:
        if not instr.upper().startswith("EXPOSE "):
            continue
        for token in instr[7:].strip().split():
            try:
                port = int(re.sub(r"/.*", "", token))
            except ValueError:
                continue
            if port < 1024:
                findings.append(Finding(
                    "INFO", "PRIVILEGED_PORT",
                    f"EXPOSE on privileged port {port} at line {lineno} — requires root or CAP_NET_BIND_SERVICE.",
                    lineno, "Use a port >= 1024 and map it with -p at runtime."
                ))
    return findings


def _check_healthcheck(instrs: List[Tuple[int, str]]) -> List[Finding]:
    if not any(i.upper().startswith("HEALTHCHECK") for _, i in instrs):
        return [Finding(
            "INFO", "NO_HEALTHCHECK",
            "No HEALTHCHECK instruction — orchestrators cannot auto-detect container health.",
            0, "Add: HEALTHCHECK CMD curl -f http://localhost/ || exit 1"
        )]
    return []

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[96m",
    "INFO":     "\033[37m",
    "RESET":    "\033[0m",
}


def _print_report(findings: List[Finding], path: str) -> None:
    findings = sorted(findings, key=lambda f: _SEV_RANK.get(f.severity, 99))
    print(f"\n{'='*62}")
    print(f"  Dockerfile Security Scan -- {path}")
    print(f"{'='*62}")
    if not findings:
        print("\n  No issues found.\n")
        return
    counts: dict = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  " + "  ".join(
        f"{_COLORS[s]}{counts[s]} {s}{_COLORS['RESET']}"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if s in counts
    )
    print(summary + "\n")
    for f in findings:
        c, r = _COLORS.get(f.severity, ""), _COLORS["RESET"]
        loc = f" (line {f.line})" if f.line else ""
        print(f"  {c}[{f.severity}]{r} {f.rule}{loc}")
        print(f"    {f.message}")
        print(f"    Fix: {f.fix}\n")

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def scan(path: str) -> int:
    if not os.path.isfile(path):
        print(f"Error: '{path}' not found.")
        return 2
    try:
        instrs = parse_dockerfile(path)
    except Exception as exc:
        print(f"Parse error: {exc}")
        return 2

    findings: List[Finding] = []
    for check in (
        _check_user, _check_base_images, _check_add,
        _check_secrets, _check_run, _check_expose, _check_healthcheck,
    ):
        findings.extend(check(instrs))

    _print_report(findings, path)
    return 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "Dockerfile"
    sys.exit(scan(target))
