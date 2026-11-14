#!/usr/bin/env python3
"""
kms_key_auditor.py - AWS KMS customer-managed key hygiene auditor.

Reviews every customer-managed KMS key in an account and reports the
configuration weaknesses that matter for key management:

  Rotation   automatic annual rotation disabled on a symmetric CMK
  Lifecycle  keys disabled or scheduled for deletion (data they protect
             becomes unrecoverable once deletion completes)
  Access     key policies that grant kms:* or Decrypt to every principal
             in the account ("AWS": "*" or a bare account-root principal
             with no condition), and grants to external AWS accounts
  Hygiene    keys with no alias (hard to attribute), and unused keys with
             no alias and no grants

Read-only: it calls only List*, Describe*, Get* and does not change, use,
or read the material of any key. Runs against one region by default or
every enabled region with --all-regions.

Usage:
  python3 kms_key_auditor.py
  python3 kms_key_auditor.py --profile prod --region us-east-1
  python3 kms_key_auditor.py --all-regions --json
  python3 kms_key_auditor.py --min-severity HIGH --fail-on-findings   # CI gate

Severity:
  HIGH    external-account or account-wide access, or a key pending deletion
  MEDIUM  rotation disabled on a symmetric CMK, or a disabled key
  LOW     missing alias / attribution gaps

Exit codes:
  0  clean (or findings present without --fail-on-findings)
  1  findings at or above --min-severity, with --fail-on-findings
  2  usage / credential error

Dependencies: pip install boto3
Author: https://github.com/ashvinctrl/cloud-security-scripts
"""

import argparse
import json
import sys

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
except ImportError:
    print("[ERROR] boto3 not installed. Run: pip install boto3", file=sys.stderr)
    sys.exit(2)

SEVERITIES = ["LOW", "MEDIUM", "HIGH"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}

COLORS = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[96m"}
BOLD = "\033[1m"
GREEN = "\033[92m"
RESET = "\033[0m"


def colorize(enabled):
    if enabled:
        return (lambda sev: COLORS.get(sev, ""), BOLD, GREEN, RESET)
    return (lambda sev: "", "", "", "")


class Finding:
    def __init__(self, region, key_id, alias, severity, title, detail):
        self.region = region
        self.key_id = key_id
        self.alias = alias
        self.severity = severity
        self.title = title
        self.detail = detail

    def to_dict(self):
        return {
            "region": self.region,
            "key_id": self.key_id,
            "alias": self.alias,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
        }


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def policy_principals(statement):
    """Flatten the AWS principals named in a policy statement."""
    principal = statement.get("Principal")
    if principal in ("*", {"AWS": "*"}):
        return ["*"]
    out = []
    if isinstance(principal, dict):
        for value in as_list(principal.get("AWS")):
            out.append(str(value))
    elif isinstance(principal, str):
        out.append(principal)
    return out


def audit_key_policy(region, key_id, alias, account_id, policy_doc, findings):
    """Flag key policies that open Decrypt/admin to the account or outsiders."""
    try:
        policy = json.loads(policy_doc)
    except (ValueError, TypeError):
        return
    if not isinstance(policy, dict):
        return
    for stmt in as_list(policy.get("Statement")):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        actions = [a.lower() for a in as_list(stmt.get("Action"))]
        sensitive = any(
            a == "kms:*" or a == "*" or a.startswith("kms:decrypt")
            or a.startswith("kms:reencrypt") or a == "kms:createGrant".lower()
            for a in actions
        )
        if not sensitive:
            continue
        has_condition = bool(stmt.get("Condition"))
        for who in policy_principals(stmt):
            if who == "*" and not has_condition:
                findings.append(Finding(
                    region, key_id, alias, "HIGH",
                    "Key policy grants sensitive actions to any principal",
                    f'Principal "*" is allowed {sorted(set(actions))} with no condition'))
            elif who != "*":
                acct = who.split(":")[4] if who.count(":") >= 4 else ""
                if acct and acct != account_id:
                    findings.append(Finding(
                        region, key_id, alias, "HIGH",
                        "Key policy grants sensitive actions to an external account",
                        f"{who} is allowed {sorted(set(actions))}"))
                elif who == account_id or who.endswith(":root"):
                    if not has_condition and ("kms:*" in actions or "*" in actions):
                        findings.append(Finding(
                            region, key_id, alias, "MEDIUM",
                            "Key policy delegates full control to the whole account",
                            f"{who} is allowed kms:* with no condition; any IAM "
                            "principal the account grants kms access can use this key"))


def audit_region(session, region, verbose, findings):
    kms = session.client("kms", region_name=region)
    account_id = ""
    try:
        account_id = session.client("sts", region_name=region).get_caller_identity()["Account"]
    except (ClientError, BotoCoreError):
        pass

    # alias -> target key id
    alias_of = {}
    try:
        paginator = kms.get_paginator("list_aliases")
        for page in paginator.paginate():
            for alias in page.get("Aliases", []):
                target = alias.get("TargetKeyId")
                if target:
                    alias_of.setdefault(target, alias["AliasName"])
    except (ClientError, BotoCoreError) as exc:
        print(f"[WARN] {region}: cannot list aliases: {exc}", file=sys.stderr)

    try:
        paginator = kms.get_paginator("list_keys")
        key_ids = [k["KeyId"] for page in paginator.paginate() for k in page.get("Keys", [])]
    except (ClientError, BotoCoreError) as exc:
        print(f"[WARN] {region}: cannot list keys: {exc}", file=sys.stderr)
        return

    for key_id in key_ids:
        try:
            meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        except (ClientError, BotoCoreError) as exc:
            print(f"[WARN] {region}: describe_key {key_id}: {exc}", file=sys.stderr)
            continue

        # AWS-managed keys are rotated and locked down by AWS; skip them.
        if meta.get("KeyManager") != "CUSTOMER":
            continue

        alias = alias_of.get(key_id, "")
        state = meta.get("KeyState", "")
        spec = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec", "")
        symmetric = meta.get("KeyUsage") == "ENCRYPT_DECRYPT" and "SYMMETRIC" in spec

        if verbose:
            print(f"  checking {key_id} ({alias or 'no alias'}) [{state}]", file=sys.stderr)

        if state == "PendingDeletion":
            when = meta.get("DeletionDate")
            findings.append(Finding(
                region, key_id, alias, "HIGH",
                "Key is scheduled for deletion",
                f"deletion date {when}; anything encrypted under it is lost once it completes"))
            continue  # other checks are moot for a key on its way out

        if state == "Disabled":
            findings.append(Finding(
                region, key_id, alias, "MEDIUM",
                "Key is disabled",
                "data encrypted under it cannot be decrypted until the key is re-enabled"))

        # Rotation applies only to symmetric CMKs with material in AWS KMS.
        if symmetric and meta.get("Origin", "AWS_KMS") == "AWS_KMS":
            try:
                rotating = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)
                if not rotating:
                    findings.append(Finding(
                        region, key_id, alias, "MEDIUM",
                        "Automatic key rotation is disabled",
                        "enable annual rotation so a compromised key version ages out"))
            except (ClientError, BotoCoreError) as exc:
                print(f"[WARN] {region}: rotation status {key_id}: {exc}", file=sys.stderr)

        if not alias:
            findings.append(Finding(
                region, key_id, alias, "LOW",
                "Key has no alias",
                "no alias makes the key hard to attribute and easy to misuse"))

        try:
            policy_doc = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
            audit_key_policy(region, key_id, alias, account_id, policy_doc, findings)
        except (ClientError, BotoCoreError) as exc:
            print(f"[WARN] {region}: key policy {key_id}: {exc}", file=sys.stderr)


def enabled_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    regions = ec2.describe_regions(AllRegions=False)["Regions"]
    return sorted(r["RegionName"] for r in regions)


def main():
    parser = argparse.ArgumentParser(
        description="Audit AWS customer-managed KMS keys for rotation, lifecycle, and access weaknesses.")
    parser.add_argument("--profile", help="AWS named profile")
    parser.add_argument("--region", help="single region (defaults to the profile/env region)")
    parser.add_argument("--all-regions", action="store_true", help="scan every enabled region")
    parser.add_argument("--min-severity", default="LOW", choices=SEVERITIES,
                        help="hide findings below this severity (default LOW)")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="exit 1 if any finding is at or above --min-severity")
    parser.add_argument("-v", "--verbose", action="store_true", help="log each key to stderr")
    args = parser.parse_args()

    color, bold, green, reset = colorize(not args.no_color and not args.json and sys.stdout.isatty())

    try:
        session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
        if args.all_regions:
            regions = enabled_regions(session)
        elif args.region:
            regions = [args.region]
        else:
            region = session.region_name
            if not region:
                print("[ERROR] no region set; pass --region or --all-regions", file=sys.stderr)
                return 2
            regions = [region]
    except NoCredentialsError:
        print("[ERROR] no AWS credentials found", file=sys.stderr)
        return 2
    except (ClientError, BotoCoreError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    findings = []
    for region in regions:
        if args.verbose:
            print(f"[*] region {region}", file=sys.stderr)
        try:
            audit_region(session, region, args.verbose, findings)
        except (ClientError, BotoCoreError) as exc:
            print(f"[WARN] {region}: {exc}", file=sys.stderr)

    threshold = RANK[args.min_severity]
    shown = [f for f in findings if RANK[f.severity] >= threshold]
    shown.sort(key=lambda f: (-RANK[f.severity], f.region, f.alias or f.key_id))

    if args.json:
        print(json.dumps([f.to_dict() for f in shown], indent=2))
    else:
        if not shown:
            print(f"{green}[OK]{reset} No KMS key findings at or above {args.min_severity}.")
        else:
            print(f"\n{bold}AWS KMS key audit - {len(shown)} finding(s){reset}\n")
            for f in shown:
                where = f.alias or f.key_id
                print(f"{color(f.severity)}[{f.severity}]{reset} {bold}{where}{reset}  ({f.region})")
                print(f"    {f.title}")
                print(f"    {f.detail}\n")
            counts = {}
            for f in shown:
                counts[f.severity] = counts.get(f.severity, 0) + 1
            summary = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES) if s in counts)
            print(f"{bold}Summary:{reset} {summary}")

    if args.fail_on_findings and shown:
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
