#!/usr/bin/env python3
"""
AWS IAM Security Auditor
Checks IAM users, roles, and policies for common misconfigurations.

Usage:
    python3 aws_iam_audit.py
    python3 aws_iam_audit.py --profile my-aws-profile --region us-east-1

Dependencies:
    pip install boto3
"""

import argparse
import sys
import time
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("[ERROR] boto3 not installed. Run: pip install boto3")
    sys.exit(1)


SEP = "-" * 60
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"


def tag(color, label, msg):
    return f"{color}[{label}]{RESET} {msg}"


def days_since(dt):
    if not dt:
        return None
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt).days


def audit_root(iam):
    print(f"\n{BOLD}=== Root Account ==={RESET}")
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0):
            print(tag(GREEN, "OK", "Root MFA enabled"))
        else:
            print(tag(RED, "FAIL", "Root account MFA is NOT enabled"))
        if summary.get("AccountAccessKeysPresent", 0):
            print(tag(RED, "FAIL", "Root account has active access keys — remove them immediately"))
        else:
            print(tag(GREEN, "OK", "No access keys on root account"))
    except ClientError as e:
        print(tag(YELLOW, "WARN", f"Cannot read account summary: {e}"))


def audit_password_policy(iam):
    print(f"\n{BOLD}=== Password Policy ==={RESET}")
    try:
        p = iam.get_account_password_policy()["PasswordPolicy"]
        checks = [
            ("MinimumPasswordLength",      14,   ">=", "Min length >= 14"),
            ("RequireUppercaseCharacters", True,  "==", "Require uppercase"),
            ("RequireLowercaseCharacters", True,  "==", "Require lowercase"),
            ("RequireNumbers",             True,  "==", "Require numbers"),
            ("RequireSymbols",             True,  "==", "Require symbols"),
            ("MaxPasswordAge",             90,   "<=", "Password expiry <= 90 days"),
            ("PasswordReusePrevention",    5,    ">=", "Reuse prevention >= 5"),
        ]
        for key, threshold, op, label in checks:
            val = p.get(key)
            if val is None:
                print(tag(YELLOW, "WARN", f"{label}: not configured"))
                continue
            if op == "==" and val == threshold:
                print(tag(GREEN, "OK", label))
            elif op == "==" and val != threshold:
                print(tag(RED, "FAIL", f"{label}: disabled"))
            elif op == ">=" and val >= threshold:
                print(tag(GREEN, "OK", f"{label}: {val}"))
            elif op == ">=" and val < threshold:
                print(tag(RED, "FAIL", f"{label}: {val} (need >= {threshold})"))
            elif op == "<=" and val <= threshold:
                print(tag(GREEN, "OK", f"{label}: {val}"))
            elif op == "<=" and val > threshold:
                print(tag(RED, "FAIL", f"{label}: {val} (need <= {threshold})"))
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchEntity":
            print(tag(RED, "FAIL", "No password policy set — configure one immediately"))
        else:
            print(tag(YELLOW, "WARN", str(e)))


def audit_users(iam):
    print(f"\n{BOLD}=== IAM Users ==={RESET}")
    users = iam.list_users()["Users"]
    if not users:
        print(tag(GREEN, "OK", "No IAM users"))
        return

    findings = []
    for user in users:
        name = user["UserName"]
        issues = []

        if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
            issues.append("no MFA device attached")

        for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
            kid = key["AccessKeyId"][:12] + "..."
            if key["Status"] == "Active":
                age = days_since(key["CreateDate"])
                if age and age > 90:
                    issues.append(f"access key {kid} is {age} days old (rotate >90d keys)")
            else:
                issues.append(f"inactive key {kid} should be deleted")

        last = user.get("PasswordLastUsed")
        if last:
            idle = days_since(last)
            if idle and idle > 90:
                issues.append(f"console unused for {idle} days (consider deactivating)")
        else:
            created_days = days_since(user["CreateDate"])
            if created_days and created_days > 30:
                issues.append("console password never used (>30 days since creation)")

        if issues:
            findings.append((name, issues))
        else:
            print(tag(GREEN, "OK", name))

    for name, issues in findings:
        print(tag(RED, "FAIL", f"{name}:"))
        for issue in issues:
            print(f"       - {issue}")


def audit_policies(iam):
    print(f"\n{BOLD}=== Wildcard Policy Check ==={RESET}")
    risky = []
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            doc = iam.get_policy_version(
                PolicyArn=policy["Arn"],
                VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]["Document"]

            stmts = doc.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]

            for stmt in stmts:
                if stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                if "*" in actions and "*" in resources:
                    risky.append((policy["PolicyName"], "Action:* + Resource:* (full admin grant)"))
                elif "*" in actions:
                    risky.append((policy["PolicyName"], f"Wildcard Action on {resources}"))

    if risky:
        for name, reason in risky:
            print(tag(RED, "FAIL", f"{name}: {reason}"))
    else:
        print(tag(GREEN, "OK", "No customer-managed policies with dangerous wildcards"))


def main():
    parser = argparse.ArgumentParser(description="AWS IAM Security Auditor")
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    try:
        iam = session.client("iam")
        iam.get_account_summary()
    except NoCredentialsError:
        print(tag(RED, "ERROR", "No AWS credentials. Set AWS_ACCESS_KEY_ID/SECRET or configure ~/.aws/credentials"))
        sys.exit(1)
    except ClientError as e:
        print(tag(RED, "ERROR", str(e)))
        sys.exit(1)

    print(f"\n{BOLD}AWS IAM Security Audit{RESET}")
    print(f"Profile: {args.profile or 'default'}  |  Region: {args.region}")
    print(f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(SEP)

    audit_root(iam)
    audit_password_policy(iam)
    audit_users(iam)
    audit_policies(iam)

    print(f"\n{SEP}")
    print(f"{BOLD}Audit complete.{RESET}\n")


if __name__ == "__main__":
    main()
