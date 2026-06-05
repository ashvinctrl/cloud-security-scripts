#!/usr/bin/env python3
"""
AWS EC2 Security Group Auditor
Purpose: Scan all EC2 security groups for overly permissive inbound rules,
         unrestricted access to sensitive ports, and orphaned (unused) groups.
Usage:   python3 ec2_sg_auditor.py [--profile PROFILE] [--region REGION] [--output {text,json}]
Dependencies: boto3 (pip install boto3), AWS credentials configured
"""

import boto3
import json
import argparse
import sys
from datetime import datetime

SENSITIVE_PORTS = {
    22:    "SSH",
    23:    "Telnet",
    3389:  "RDP",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    1433:  "MSSQL",
    27017: "MongoDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch-transport",
    2379:  "etcd",
    2380:  "etcd-peer",
    5900:  "VNC",
    5984:  "CouchDB",
    11211: "Memcached",
}

SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def get_all_security_groups(ec2):
    groups = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        groups.extend(page["SecurityGroups"])
    return groups


def get_used_sg_ids(ec2):
    """Return set of SG IDs attached to any resource (instances, ENIs, etc.)."""
    used = set()
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for r in page["Reservations"]:
            for inst in r["Instances"]:
                for sg in inst.get("SecurityGroups", []):
                    used.add(sg["GroupId"])
    paginator = ec2.get_paginator("describe_network_interfaces")
    for page in paginator.paginate():
        for eni in page["NetworkInterfaces"]:
            for sg in eni.get("Groups", []):
                used.add(sg["GroupId"])
    return used


def audit_security_group(sg, used_sg_ids):
    findings = []
    sg_id   = sg["GroupId"]
    sg_name = sg.get("GroupName", "unnamed")
    is_default = sg_name == "default"

    if sg_id not in used_sg_ids and not is_default:
        findings.append({
            "group_id":   sg_id,
            "group_name": sg_name,
            "severity":   SEVERITY["LOW"],
            "issue":      "Orphaned security group - not attached to any resource",
            "rule":       None,
        })

    for rule in sg.get("IpPermissions", []):
        protocol  = rule.get("IpProtocol", "")
        from_port = rule.get("FromPort", 0)
        to_port   = rule.get("ToPort", 65535)

        open_cidrs = (
            [ip["CidrIp"]   for ip in rule.get("IpRanges",   []) if ip["CidrIp"] in ("0.0.0.0/0", "::/0")]
            + [ip["CidrIpv6"] for ip in rule.get("Ipv6Ranges", []) if ip["CidrIpv6"] == "::/0"]
        )

        for cidr in open_cidrs:
            if protocol == "-1":
                severity = SEVERITY["CRITICAL"]
                desc     = f"All traffic open to {cidr} (any port, any protocol)"
                port_str = "ALL"
            else:
                matched = [p for p in SENSITIVE_PORTS if from_port <= p <= to_port]
                port_str = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                if matched:
                    severity = SEVERITY["CRITICAL"]
                    names    = ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in matched)
                    desc     = f"Sensitive port(s) [{names}] open to {cidr}"
                elif from_port == 0 and to_port == 65535:
                    severity = SEVERITY["HIGH"]
                    desc     = f"All {protocol.upper()} ports open to {cidr}"
                else:
                    severity = SEVERITY["MEDIUM"] if not is_default else SEVERITY["HIGH"]
                    desc     = f"Port {port_str}/{protocol.upper()} open to {cidr}"

            findings.append({
                "group_id":   sg_id,
                "group_name": sg_name,
                "severity":   severity,
                "issue":      desc,
                "rule":       {"port": port_str, "protocol": protocol, "cidr": cidr},
            })

    return findings


def print_text_report(findings, region, account_id):
    counts = {s: 0 for s in SEVERITY.values()}
    for f in findings:
        counts[f["severity"]] += 1

    print(f"\n{'='*70}")
    print(f"  AWS EC2 Security Group Audit Report")
    print(f"  Region:  {region}   Account: {account_id}")
    print(f"  Date:    {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Total findings: {len(findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev]:
            print(f"    {sev}: {counts[sev]}")
    print(f"{'='*70}\n")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        bucket = [f for f in findings if f["severity"] == sev]
        if not bucket:
            continue
        print(f"[{sev}] {len(bucket)} finding(s)")
        print("-" * 60)
        for f in bucket:
            print(f"  {f['group_id']} ({f['group_name']})")
            print(f"  >> {f['issue']}")
            if f["rule"]:
                r = f["rule"]
                print(f"     port={r['port']}  proto={r['protocol']}  cidr={r['cidr']}")
            print()


def main():
    parser = argparse.ArgumentParser(
        description="Audit AWS EC2 security groups for overly permissive rules and orphaned groups"
    )
    parser.add_argument("--profile", help="AWS CLI profile name")
    parser.add_argument("--region",  default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--output",  choices=["text", "json"], default="text")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ec2 = session.client("ec2")
    sts = session.client("sts")

    try:
        account_id = sts.get_caller_identity()["Account"]
    except Exception as exc:
        print(f"[ERROR] AWS authentication failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Fetching security groups in {args.region} ...")
    sgs = get_all_security_groups(ec2)
    print(f"[*] Found {len(sgs)} security groups")

    print("[*] Resolving attached-resource map ...")
    used_ids = get_used_sg_ids(ec2)

    print("[*] Auditing rules ...\n")
    all_findings = []
    for sg in sgs:
        all_findings.extend(audit_security_group(sg, used_ids))

    if args.output == "json":
        print(json.dumps({
            "account":      account_id,
            "region":       args.region,
            "timestamp":    datetime.utcnow().isoformat() + "Z",
            "total_groups": len(sgs),
            "findings":     all_findings,
        }, indent=2))
    else:
        print_text_report(all_findings, args.region, account_id)

    critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    sys.exit(1 if critical else 0)


if __name__ == "__main__":
    main()
