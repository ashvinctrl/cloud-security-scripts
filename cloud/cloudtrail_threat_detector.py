#!/usr/bin/env python3
"""
cloudtrail_threat_detector.py
Purpose : Analyze AWS CloudTrail logs for suspicious security events
Usage   : python3 cloudtrail_threat_detector.py [--days 7] [--region us-east-1] [--output report.json]
Deps    : boto3  (pip install boto3)
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from collections import defaultdict

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    sys.exit("ERROR: boto3 not installed. Run: pip install boto3")

# ── Threat signatures ──────────────────────────────────────────────────────────

CRITICAL_EVENTS = {
    "ConsoleLogin", "CreateUser", "CreateAccessKey",
    "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutRolePolicy",
    "DeleteTrail", "StopLogging", "UpdateTrail", "DeleteFlowLogs",
}

ROOT_ACTIONS = {"ConsoleLogin", "CreateUser", "CreateAccessKey"}

DESTRUCTIVE_EVENTS = {
    "DeleteTrail", "StopLogging", "DeleteBucket",
    "DeleteDBInstance", "TerminateInstances",
    "DeleteSecret", "DeleteKey",
}

RECON_EVENTS = {
    "DescribeInstances", "ListBuckets", "ListUsers",
    "ListRoles", "GetAccountSummary", "ListAttachedUserPolicies",
    "ListPolicies", "GetCredentialReport",
}

# ── Helpers ────────────────────────────────────────────────────────────────────

def get_events(client, start_time, end_time):
    """Page through CloudTrail LookupEvents for the given window."""
    events = []
    paginator = client.get_paginator("lookup_events")
    for page in paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={"PageSize": 50},
    ):
        for raw in page.get("Events", []):
            detail = json.loads(raw.get("CloudTrailEvent", "{}"))
            events.append(detail)
    return events


def classify(event):
    """Return threat tags for a single CloudTrail event record."""
    tags = []
    name = event.get("eventName", "")
    user_type = event.get("userIdentity", {}).get("type", "")
    error = event.get("errorCode", "")

    if user_type == "Root" and name in ROOT_ACTIONS:
        tags.append("ROOT_ACCOUNT_USAGE")
    if error in ("AccessDenied", "UnauthorizedAccess"):
        tags.append("ACCESS_DENIED")
    if name in DESTRUCTIVE_EVENTS:
        tags.append("DESTRUCTIVE_ACTION")
    if name in CRITICAL_EVENTS and user_type != "Root":
        tags.append("PRIVILEGE_CHANGE")
    if name in RECON_EVENTS:
        tags.append("RECON_ACTIVITY")
    if name == "ConsoleLogin" and event.get("responseElements", {}).get("ConsoleLogin") == "Failure":
        tags.append("FAILED_LOGIN")

    return tags


def summarise(events):
    """Build a structured findings report from raw events."""
    findings = []
    access_denied_by_ip = defaultdict(int)
    recon_by_principal = defaultdict(int)

    for ev in events:
        tags = classify(ev)
        if not tags:
            continue

        principal = (
            ev.get("userIdentity", {}).get("arn")
            or ev.get("userIdentity", {}).get("principalId")
            or "unknown"
        )
        source_ip = ev.get("sourceIPAddress", "unknown")

        if "ACCESS_DENIED" in tags:
            access_denied_by_ip[source_ip] += 1
        if "RECON_ACTIVITY" in tags:
            recon_by_principal[principal] += 1

        high_sev = {"ROOT_ACCOUNT_USAGE", "DESTRUCTIVE_ACTION", "PRIVILEGE_CHANGE", "FAILED_LOGIN"}
        if tags and high_sev.intersection(tags):
            findings.append({
                "time": ev.get("eventTime"),
                "event": ev.get("eventName"),
                "region": ev.get("awsRegion"),
                "principal": principal,
                "source_ip": source_ip,
                "tags": tags,
                "user_agent": ev.get("userAgent", ""),
            })

    for ip, count in access_denied_by_ip.items():
        if count >= 5:
            findings.append({
                "time": "aggregated",
                "event": "MULTIPLE_ACCESS_DENIED",
                "source_ip": ip,
                "count": count,
                "tags": ["BRUTE_FORCE_CANDIDATE"],
            })

    for principal, count in recon_by_principal.items():
        if count >= 10:
            findings.append({
                "time": "aggregated",
                "event": "HIGH_RECON_VOLUME",
                "principal": principal,
                "count": count,
                "tags": ["RECON_SPIKE"],
            })

    return findings


def print_report(findings, days):
    severity_order = {
        "ROOT_ACCOUNT_USAGE": 0, "DESTRUCTIVE_ACTION": 1,
        "BRUTE_FORCE_CANDIDATE": 2, "PRIVILEGE_CHANGE": 3,
        "RECON_SPIKE": 4, "FAILED_LOGIN": 5,
        "ACCESS_DENIED": 6, "RECON_ACTIVITY": 7,
    }
    findings.sort(key=lambda f: min((severity_order.get(t, 99) for t in f["tags"]), default=99))

    print(f"\n{'='*64}")
    print(f"  CloudTrail Threat Report  |  last {days} day(s)")
    print(f"{'='*64}")

    if not findings:
        print("  No suspicious activity detected.")
        return

    for i, f in enumerate(findings, 1):
        print(f"\n[{i}] {' | '.join(f['tags'])}")
        for k in ("time", "event", "region", "principal", "source_ip", "count", "user_agent"):
            if v := f.get(k):
                print(f"    {k:<12}: {v}")

    print(f"\nTotal findings: {len(findings)}")
    print("="*64)


def main():
    parser = argparse.ArgumentParser(description="Detect threats in AWS CloudTrail logs")
    parser.add_argument("--days", type=int, default=1, help="Look-back window in days (default: 1)")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--output", help="Save JSON report to this file path")
    parser.add_argument("--profile", help="AWS CLI profile name")
    args = parser.parse_args()

    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile

    try:
        session = boto3.Session(**session_kwargs)
        client = session.client("cloudtrail", region_name=args.region)
    except NoCredentialsError:
        sys.exit("ERROR: AWS credentials not configured. Run 'aws configure' first.")

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=args.days)

    print(f"Fetching CloudTrail events from {start_time:%Y-%m-%d %H:%M} UTC ...")
    try:
        events = get_events(client, start_time, end_time)
    except ClientError as e:
        sys.exit(f"ERROR: {e}")

    print(f"Analysed {len(events)} event(s).")
    findings = summarise(events)
    print_report(findings, args.days)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(findings, fh, indent=2, default=str)
        print(f"\nJSON report saved to: {args.output}")


if __name__ == "__main__":
    main()
