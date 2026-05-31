#!/usr/bin/env python3
"""
GitHub Actions Workflow Security Auditor
=========================================
Purpose : Scan .github/workflows/ YAML files for common security
          misconfigurations: hardcoded secrets, unpinned action refs,
          overly-permissive tokens, dangerous triggers, and script injection.
Usage   : python github_actions_audit.py [--path /path/to/repo]
Deps    : pip install pyyaml colorama
"""

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("Missing deps: pip install pyyaml colorama")
    sys.exit(1)

SECRET_PATTERNS = [
    (r"(?i)(password|secret|token|api_key|apikey|private_key)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{8,}",
     "Possible hardcoded secret"),
    (r"(?i)aws_access_key_id\s*[:=]\s*[A-Z0-9]{20}", "AWS Access Key ID"),
    (r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+]{40}", "AWS Secret Access Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"glpat-[A-Za-z0-9\-]{20}", "GitLab Personal Access Token"),
]

DANGEROUS_TRIGGERS = {"pull_request_target", "workflow_run"}
PINNED_HASH_RE = re.compile(r"^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.\-]+@[0-9a-f]{40}$")
VERSION_TAG_RE  = re.compile(r"^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.\-]+@v\d+")


class Finding:
    COLORS = {"HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.CYAN, "INFO": Fore.WHITE}

    def __init__(self, severity, file, message, line=None):
        self.severity = severity
        self.file = file
        self.message = message
        self.line = line

    def __str__(self):
        loc = f":{self.line}" if self.line else ""
        c = self.COLORS.get(self.severity, "")
        return f"{c}[{self.severity}]{Style.RESET_ALL} {self.file}{loc} -- {self.message}"


def check_hardcoded_secrets(raw, filename):
    findings = []
    for lineno, line in enumerate(raw.splitlines(), 1):
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding("HIGH", filename, label, lineno))
    return findings


def check_triggers(workflow, filename):
    findings = []
    on = workflow.get("on") or workflow.get(True)
    if not on:
        return findings
    trigger_keys = on if isinstance(on, dict) else {t: {} for t in (on if isinstance(on, list) else [on])}
    for trigger in DANGEROUS_TRIGGERS:
        if trigger in trigger_keys:
            findings.append(Finding(
                "HIGH", filename,
                f"Dangerous trigger '{trigger}' grants write access to PRs from forks"
            ))
    return findings


def check_permissions(workflow, filename):
    findings = []
    perms = workflow.get("permissions")
    if isinstance(perms, str) and perms == "write-all":
        findings.append(Finding("HIGH", filename, "Top-level permissions: write-all (overly broad)"))
    elif isinstance(perms, dict):
        for key, val in perms.items():
            if str(val).lower() == "write":
                findings.append(Finding("MEDIUM", filename,
                    f"Top-level write permission: {key}: write -- scope to job level"))
    return findings


def check_actions_pinning(workflow, filename):
    findings = []
    for job in (workflow.get("jobs") or {}).values():
        for step in (job.get("steps") or []):
            uses = step.get("uses", "")
            if not uses or uses.startswith(".") or uses.startswith("docker://"):
                continue
            if PINNED_HASH_RE.match(uses):
                pass  # fully pinned to commit SHA -- best practice
            elif VERSION_TAG_RE.match(uses):
                findings.append(Finding("LOW", filename,
                    f"Action pinned to mutable version tag (not SHA): {uses}"))
            else:
                findings.append(Finding("MEDIUM", filename,
                    f"Action not pinned to a commit SHA: {uses}"))
    return findings


def check_script_injection(raw, filename):
    findings = []
    in_run = False
    for lineno, line in enumerate(raw.splitlines(), 1):
        if re.match(r'\s*run\s*:', line):
            in_run = True
        if in_run and re.search(
            r'\$\{\{.*?(github\.event\.|github\.head_ref|github\.base_ref|github\.ref_name)', line
        ):
            findings.append(Finding("HIGH", filename,
                "Script injection risk: untrusted github context in run step", lineno))
        stripped = line.strip()
        if in_run and stripped and not line.startswith(" ") and "run" not in line:
            in_run = False
    return findings


def check_env_from_event(raw, filename):
    findings = []
    for lineno, line in enumerate(raw.splitlines(), 1):
        if re.search(r':\s*\$\{\{\s*github\.event\.\S+\s*\}\}', line) and \
           re.search(r'(?i)(token|secret|password|key|auth)', line):
            findings.append(Finding("MEDIUM", filename,
                "Sensitive env var sourced from github.event (untrusted user input)", lineno))
    return findings


def audit(repo_path):
    wf_dir = repo_path / ".github" / "workflows"
    if not wf_dir.exists():
        print(f"No .github/workflows/ found under {repo_path}")
        sys.exit(1)

    workflows = sorted(list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml")))
    if not workflows:
        print("No workflow YAML files found.")
        return

    all_findings = []
    for wf_file in workflows:
        raw = wf_file.read_text(encoding="utf-8", errors="replace")
        name = wf_file.name
        try:
            data = yaml.safe_load(raw) or {}
        except yaml.YAMLError as e:
            all_findings.append(Finding("INFO", name, f"YAML parse error: {e}"))
            continue

        all_findings += check_hardcoded_secrets(raw, name)
        all_findings += check_triggers(data, name)
        all_findings += check_permissions(data, name)
        all_findings += check_actions_pinning(data, name)
        all_findings += check_script_injection(raw, name)
        all_findings += check_env_from_event(raw, name)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        print(f)

    print()
    print(
        f"Scanned {len(workflows)} workflow(s)  |  "
        f"{Fore.RED}{counts['HIGH']} HIGH{Style.RESET_ALL}  "
        f"{Fore.YELLOW}{counts['MEDIUM']} MEDIUM{Style.RESET_ALL}  "
        f"{Fore.CYAN}{counts['LOW']} LOW{Style.RESET_ALL}"
    )

    if not all_findings:
        print(f"{Fore.GREEN}No issues found -- workflows look clean.{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="Audit GitHub Actions workflows for security misconfigurations."
    )
    parser.add_argument(
        "--path", default=".", metavar="REPO_PATH",
        help="Path to the repository root (default: current directory)"
    )
    args = parser.parse_args()
    audit(Path(args.path).resolve())


if __name__ == "__main__":
    main()