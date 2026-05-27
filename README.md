# cloud-security-scripts

Practical security automation scripts for AWS, Azure, and GCP — one script at a time.

## Scripts

| Script | Cloud | Description |
|--------|-------|-------------|
| [aws_s3_audit.py](aws_s3_audit.py) | AWS | Audits all S3 buckets for public access, encryption, versioning, logging, and ACL misconfigs |

## Usage

```bash
pip install boto3
aws configure   # set up your credentials
python aws_s3_audit.py
```

## Checks Covered

- Public access block configuration
- Default encryption
- Versioning status
- Access logging
- Bucket ACL (detects AllUsers / AuthenticatedUsers grants)

## Contributing

PRs welcome. Each script should be standalone and runnable with minimal setup.
