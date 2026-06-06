#!/usr/bin/env python3
"""
Terraform Drift Detector
========================
Purpose : Detect infrastructure drift by running `terraform plan` and parsing
          the output into a structured, human-readable report. Useful in CI/CD
          pipelines to catch unmanaged changes before they cause incidents.
Usage   : python terraform_drift_detector.py [--dir <tf-dir>] [--json] [--fail-on-drift]
Deps    : terraform CLI must be installed and authenticated; Python 3.8+
"""

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class ChangeType(Enum):
    ADD = "add"
    CHANGE = "change"
    DESTROY = "destroy"
    NO_OP = "no-op"
    REPLACE = "replace"


SEVERITY = {
    ChangeType.DESTROY: "CRITICAL",
    ChangeType.REPLACE: "HIGH",
    ChangeType.CHANGE: "MEDIUM",
    ChangeType.ADD: "LOW",
    ChangeType.NO_OP: "INFO",
}

COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",
    "LOW": "\033[92m",
    "INFO": "\033[37m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


@dataclass
class DriftedResource:
    address: str
    change_type: ChangeType
    reason: str = ""
    module: Optional[str] = None

    @property
    def severity(self) -> str:
        return SEVERITY[self.change_type]

    @property
    def is_module_resource(self) -> bool:
        return self.address.startswith("module.")


@dataclass
class DriftReport:
    terraform_dir: str
    drifted: list = field(default_factory=list)
    error: Optional[str] = None
    plan_summary: str = ""

    @property
    def has_drift(self) -> bool:
        return bool(self.drifted)

    @property
    def critical_count(self) -> int:
        return sum(1 for r in self.drifted if r.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for r in self.drifted if r.severity == "HIGH")


def run_terraform_init(tf_dir: str):
    result = subprocess.run(
        ["terraform", "init", "-input=false", "-no-color"],
        cwd=tf_dir,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return result.returncode == 0, result.stderr


def run_terraform_plan(tf_dir: str):
    result = subprocess.run(
        [
            "terraform", "plan",
            "-detailed-exitcode",
            "-no-color",
            "-input=false",
            "-refresh=true",
        ],
        cwd=tf_dir,
        capture_output=True,
        text=True,
        timeout=600,
    )
    return result.returncode, result.stdout, result.stderr


def parse_plan_output(stdout: str):
    resources = []
    change_pattern = re.compile(
        r"^\s{1,4}#\s+(\S+)\s+(?:will be|must be|has been)\s+(created|updated in-place|destroyed|replaced)",
        re.MULTILINE,
    )
    reason_pattern = re.compile(r"^\s+#\s+\((\w[^\)]+)\)", re.MULTILINE)

    for match in change_pattern.finditer(stdout):
        address = match.group(1)
        action_str = match.group(2)

        if "created" in action_str:
            change_type = ChangeType.ADD
        elif "destroyed" in action_str:
            change_type = ChangeType.DESTROY
        elif "replaced" in action_str:
            change_type = ChangeType.REPLACE
        else:
            change_type = ChangeType.CHANGE

        segment = stdout[match.end(): match.end() + 300]
        reason_match = reason_pattern.search(segment)
        reason = reason_match.group(1) if reason_match else ""

        module = None
        if address.startswith("module."):
            module = address.split(".")[1]

        resources.append(
            DriftedResource(
                address=address,
                change_type=change_type,
                reason=reason,
                module=module,
            )
        )
    return resources


def extract_plan_summary(stdout: str) -> str:
    for line in reversed(stdout.splitlines()):
        if line.strip().startswith("Plan:") or "No changes" in line:
            return line.strip()
    return ""


def color(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{COLORS.get(code, '')}{text}{COLORS['RESET']}"


def print_report(report: DriftReport) -> None:
    print(color("\n=== Terraform Drift Detector ===", "BOLD"))
    print(f"Directory : {report.terraform_dir}")
    print(f"Resources : {len(report.drifted)} drifted")
    if report.plan_summary:
        print(f"Summary   : {report.plan_summary}")
    print()

    if report.error:
        print(color(f"ERROR: {report.error}", "CRITICAL"))
        return

    if not report.has_drift:
        print(color("No drift detected. Infrastructure matches Terraform state.", "LOW"))
        return

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    grouped = {s: [] for s in severity_order}
    for r in report.drifted:
        grouped[r.severity].append(r)

    for sev in severity_order:
        items = grouped[sev]
        if not items:
            continue
        print(color(f"[{sev}] {len(items)} resource(s):", sev))
        for r in items:
            line = f"  {r.change_type.value.upper():10s} {r.address}"
            if r.reason:
                line += f"  ({r.reason})"
            print(color(line, sev))
        print()

    if report.critical_count > 0:
        print(color(f"WARNING: {report.critical_count} resource(s) will be DESTROYED.", "CRITICAL"))
    if report.high_count > 0:
        print(color(f"WARNING: {report.high_count} resource(s) will be REPLACED (destroy+create).", "HIGH"))


def analyze_directory(tf_dir: str, skip_init: bool = False) -> DriftReport:
    report = DriftReport(terraform_dir=tf_dir)

    if not Path(tf_dir).exists():
        report.error = f"Directory not found: {tf_dir}"
        return report

    tf_files = list(Path(tf_dir).glob("*.tf"))
    if not tf_files:
        report.error = f"No .tf files found in {tf_dir}"
        return report

    if not skip_init:
        print("Running terraform init...")
        ok, err = run_terraform_init(tf_dir)
        if not ok:
            report.error = f"terraform init failed: {err}"
            return report

    print("Running terraform plan (this may take a while)...")
    rc, stdout, stderr = run_terraform_plan(tf_dir)

    if rc == 1:
        report.error = stderr or "terraform plan returned an error"
        return report

    report.plan_summary = extract_plan_summary(stdout)
    if rc == 2:
        report.drifted = parse_plan_output(stdout)

    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect Terraform infrastructure drift and report it clearly."
    )
    parser.add_argument("--dir", default=".", help="Path to Terraform working directory (default: .)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output report as JSON")
    parser.add_argument("--fail-on-drift", action="store_true", help="Exit with code 1 if drift is found")
    parser.add_argument("--skip-init", action="store_true", help="Skip terraform init")
    parser.add_argument(
        "--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None,
        help="Only show resources at or above this severity level"
    )
    args = parser.parse_args()

    tf_dir = os.path.abspath(args.dir)
    report = analyze_directory(tf_dir, skip_init=args.skip_init)

    if args.severity:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        threshold = severity_order.index(args.severity)
        report.drifted = [r for r in report.drifted if severity_order.index(r.severity) <= threshold]

    if args.json_output:
        output = {
            "terraform_dir": report.terraform_dir,
            "has_drift": report.has_drift,
            "plan_summary": report.plan_summary,
            "error": report.error,
            "drifted_resources": [
                {
                    "address": r.address,
                    "change_type": r.change_type.value,
                    "severity": r.severity,
                    "reason": r.reason,
                    "module": r.module,
                }
                for r in report.drifted
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print_report(report)

    if report.error:
        return 2
    if args.fail_on_drift and report.has_drift:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
