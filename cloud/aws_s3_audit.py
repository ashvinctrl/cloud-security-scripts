#!/usr/bin/env python3
"""
AWS S3 Bucket Security Auditor
Checks all S3 buckets in your account for common misconfigurations.
Requirements: boto3, AWS credentials configured (~/.aws/credentials or env vars)
Usage: python aws_s3_audit.py
"""

import boto3
from botocore.exceptions import ClientError


def check_public_access_block(s3, bucket):
    try:
        r = s3.get_public_access_block(Bucket=bucket)
        cfg = r["PublicAccessBlockConfiguration"]
        blocked = all([
            cfg.get("BlockPublicAcls"),
            cfg.get("IgnorePublicAcls"),
            cfg.get("BlockPublicPolicy"),
            cfg.get("RestrictPublicBuckets"),
        ])
        return "PASS" if blocked else "FAIL – public access block incomplete"
    except ClientError:
        return "FAIL – no public access block configured"


def check_versioning(s3, bucket):
    r = s3.get_bucket_versioning(Bucket=bucket)
    status = r.get("Status", "Disabled")
    return "PASS" if status == "Enabled" else f"WARN – versioning {status}"


def check_encryption(s3, bucket):
    try:
        s3.get_bucket_encryption(Bucket=bucket)
        return "PASS"
    except ClientError:
        return "FAIL – no default encryption"


def check_logging(s3, bucket):
    r = s3.get_bucket_logging(Bucket=bucket)
    return "PASS" if r.get("LoggingEnabled") else "WARN – logging disabled"


def check_acl(s3, bucket):
    r = s3.get_bucket_acl(Bucket=bucket)
    for grant in r.get("Grants", []):
        grantee = grant.get("Grantee", {})
        if grantee.get("URI", "").endswith(("AllUsers", "AuthenticatedUsers")):
            return f"FAIL – bucket ACL grants public access ({grantee['URI'].split('/')[-1]})"
    return "PASS"


def audit():
    s3 = boto3.client("s3")
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]

    if not buckets:
        print("No buckets found.")
        return

    checks = {
        "Public Access Block": check_public_access_block,
        "Versioning":          check_versioning,
        "Encryption":          check_encryption,
        "Access Logging":      check_logging,
        "ACL":                 check_acl,
    }

    for bucket in buckets:
        print(f"\n{'='*55}\nBucket: {bucket}\n{'='*55}")
        for name, fn in checks.items():
            try:
                result = fn(s3, bucket)
            except Exception as e:
                result = f"ERROR – {e}"
            status_icon = "✓" if result.startswith("PASS") else ("!" if result.startswith("WARN") else "✗")
            print(f"  [{status_icon}] {name:<22} {result}")


if __name__ == "__main__":
    audit()
