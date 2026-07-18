#!/usr/bin/env python3
"""
RDS Security Auditor
====================

Audits Amazon RDS instances and snapshots for common security
misconfigurations that frequently lead to data exposure:

  Instances:
    - Publicly accessible instances (PubliclyAccessible=True)
    - Storage encryption disabled
    - Backups disabled or short retention (< 7 days)
    - Deletion protection disabled
    - Auto minor version upgrade disabled (unpatched engines)
    - IAM database authentication disabled
    - Multi-AZ disabled (availability, flagged INFO)
    - Instances running outdated/deprecated engine major versions

  Snapshots:
    - Manual snapshots shared publicly (restore=all)
    - Unencrypted manual snapshots

Usage:
    python rds_security_auditor.py                     # default profile/region
    python rds_security_auditor.py --region us-east-1
    python rds_security_auditor.py --profile prod --all-regions
    python rds_security_auditor.py --json              # machine-readable output
    python rds_security_auditor.py --fail-on-findings  # exit 1 if HIGH/CRITICAL (CI use)

Dependencies:
    pip install boto3

IAM permissions required (read-only):
    rds:DescribeDBInstances
    rds:DescribeDBSnapshots
    rds:DescribeDBSnapshotAttributes
    ec2:DescribeRegions   (only for --all-regions)
"""

import argparse
import json
import sys
from datetime import datetime, timezone

try:
    import boto3
    import botocore.exceptions
except ImportError:
    print("ERROR: boto3 is required. Install with: pip install boto3", file=sys.stderr)
    sys.exit(2)

# Engine major versions that are past (or near) end of standard support.
# Kept intentionally coarse: flag anything at or below these majors.
DEPRECATED_ENGINE_MAJORS = {
    "mysql": 5,          # MySQL 5.7 EOL for RDS standard support
    "postgres": 12,      # PostgreSQL 12 and below
    "mariadb": 10,       # MariaDB 10.x (10.4 and below are the concern; coarse flag)
    "aurora-mysql": 2,   # Aurora MySQL 2.x (MySQL 5.7 compatible)
    "aurora-postgresql": 12,
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def finding(severity, resource, issue, recommendation):
    return {
        "severity": severity,
        "resource": resource,
        "issue": issue,
        "recommendation": recommendation,
    }


def audit_instance(db):
    """Run all checks against a single DB instance description."""
    findings = []
    ident = db["DBInstanceIdentifier"]
    engine = db.get("Engine", "unknown")

    if db.get("PubliclyAccessible"):
        findings.append(finding(
            "CRITICAL", ident,
            "Instance is publicly accessible (has a public endpoint)",
            "Set PubliclyAccessible=false and place the instance in private "
            "subnets; front it with a bastion or VPN if remote access is needed",
        ))

    if not db.get("StorageEncrypted"):
        findings.append(finding(
            "HIGH", ident,
            "Storage encryption at rest is disabled",
            "Create an encrypted snapshot copy and restore to a new encrypted "
            "instance (encryption cannot be enabled in place)",
        ))

    retention = db.get("BackupRetentionPeriod", 0)
    if retention == 0:
        findings.append(finding(
            "HIGH", ident,
            "Automated backups are disabled (retention = 0)",
            "Set backup retention to at least 7 days",
        ))
    elif retention < 7:
        findings.append(finding(
            "MEDIUM", ident,
            f"Backup retention is only {retention} day(s)",
            "Increase backup retention to at least 7 days",
        ))

    if not db.get("DeletionProtection"):
        findings.append(finding(
            "MEDIUM", ident,
            "Deletion protection is disabled",
            "Enable deletion protection to prevent accidental or malicious "
            "instance deletion",
        ))

    if not db.get("AutoMinorVersionUpgrade"):
        findings.append(finding(
            "MEDIUM", ident,
            "Auto minor version upgrade is disabled",
            "Enable auto minor version upgrades so engine security patches "
            "are applied during maintenance windows",
        ))

    if not db.get("IAMDatabaseAuthenticationEnabled"):
        findings.append(finding(
            "LOW", ident,
            "IAM database authentication is disabled",
            "Enable IAM auth to use short-lived tokens instead of long-lived "
            "database passwords (supported engines only)",
        ))

    if not db.get("MultiAZ"):
        findings.append(finding(
            "INFO", ident,
            "Multi-AZ is disabled",
            "Consider Multi-AZ for production workloads to survive AZ failure",
        ))

    version = db.get("EngineVersion", "")
    major_limit = DEPRECATED_ENGINE_MAJORS.get(engine)
    if major_limit is not None and version:
        try:
            major = int(version.split(".")[0])
            if major <= major_limit:
                findings.append(finding(
                    "HIGH", ident,
                    f"Engine {engine} {version} is at or past end of standard support",
                    "Upgrade to a currently supported engine major version",
                ))
        except ValueError:
            pass

    return findings


def audit_snapshots(rds):
    """Check manual snapshots for public sharing and missing encryption."""
    findings = []
    paginator = rds.get_paginator("describe_db_snapshots")
    for page in paginator.paginate(SnapshotType="manual"):
        for snap in page["DBSnapshots"]:
            snap_id = snap["DBSnapshotIdentifier"]

            if not snap.get("Encrypted"):
                findings.append(finding(
                    "MEDIUM", snap_id,
                    "Manual snapshot is unencrypted",
                    "Copy the snapshot with encryption enabled and delete the "
                    "unencrypted original",
                ))

            # Public sharing requires a second API call per snapshot.
            try:
                attrs = rds.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snap_id
                )["DBSnapshotAttributesResult"]["DBSnapshotAttributes"]
            except botocore.exceptions.ClientError:
                continue
            for attr in attrs:
                if attr.get("AttributeName") == "restore" and \
                        "all" in attr.get("AttributeValues", []):
                    findings.append(finding(
                        "CRITICAL", snap_id,
                        "Manual snapshot is shared PUBLICLY (restorable by any AWS account)",
                        "Remove the 'all' entry from the snapshot's restore "
                        "attribute immediately and rotate any credentials "
                        "stored in the database",
                    ))
    return findings


def audit_region(session, region):
    rds = session.client("rds", region_name=region)
    findings = []
    instance_count = 0

    paginator = rds.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            instance_count += 1
            for f in audit_instance(db):
                f["region"] = region
                findings.append(f)

    for f in audit_snapshots(rds):
        f["region"] = region
        findings.append(f)

    return instance_count, findings


def get_all_regions(session):
    ec2 = session.client("ec2")
    return [r["RegionName"] for r in ec2.describe_regions()["Regions"]]


def print_report(findings, instance_count):
    print(f"\nRDS Security Audit — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"Instances scanned: {instance_count}")
    print(f"Findings: {len(findings)}\n")

    if not findings:
        print("No issues found.")
        return

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    width = max(len(f["severity"]) for f in findings)
    for f in findings:
        print(f"[{f['severity']:<{width}}] {f['region']} / {f['resource']}")
        print(f"  Issue: {f['issue']}")
        print(f"  Fix:   {f['recommendation']}\n")


def main():
    ap = argparse.ArgumentParser(description="Audit RDS instances and snapshots for security misconfigurations")
    ap.add_argument("--profile", help="AWS profile name")
    ap.add_argument("--region", help="Single region to audit (default: profile/env region)")
    ap.add_argument("--all-regions", action="store_true", help="Audit every enabled region")
    ap.add_argument("--json", action="store_true", help="Emit findings as JSON")
    ap.add_argument("--fail-on-findings", action="store_true",
                    help="Exit 1 if any HIGH or CRITICAL findings (for CI pipelines)")
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()

    if args.all_regions:
        regions = get_all_regions(session)
    elif args.region:
        regions = [args.region]
    else:
        regions = [session.region_name or "us-east-1"]

    all_findings = []
    total_instances = 0
    for region in regions:
        try:
            count, findings = audit_region(session, region)
        except botocore.exceptions.ClientError as e:
            print(f"WARNING: skipping {region}: {e.response['Error']['Code']}", file=sys.stderr)
            continue
        except botocore.exceptions.NoCredentialsError:
            print("ERROR: no AWS credentials found. Configure with 'aws configure'.", file=sys.stderr)
            sys.exit(2)
        total_instances += count
        all_findings.extend(findings)

    if args.json:
        print(json.dumps({
            "scanned_instances": total_instances,
            "finding_count": len(all_findings),
            "findings": all_findings,
        }, indent=2))
    else:
        print_report(all_findings, total_instances)

    if args.fail_on_findings and any(
            f["severity"] in ("CRITICAL", "HIGH") for f in all_findings):
        sys.exit(1)


if __name__ == "__main__":
    main()
