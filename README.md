# cloud-security-scripts

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-FF9900?style=flat-square&logo=amazon-aws&logoColor=white)](https://aws.amazon.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

Production-grade security and DevOps automation scripts across Cloud, DevOps, and Cybersecurity — each standalone, runnable with minimal setup.

## Structure

```
cloud/       AWS security audit scripts (IAM, S3, EC2, CloudTrail)
devops/      Kubernetes, Docker, CI/CD, and IaC tooling
security/    Linux hardening, web security, and secret detection
```

---

## Cloud (`cloud/`)

| Script | What it checks |
|---|---|
| [aws_s3_audit.py](cloud/aws_s3_audit.py) | S3 buckets — public access, encryption at rest, versioning, access logging, ACL misconfigs |
| [aws_iam_audit.py](cloud/aws_iam_audit.py) | IAM users and roles — console access without MFA, unused access keys, overly permissive policies, root account activity |
| [cloudtrail_threat_detector.py](cloud/cloudtrail_threat_detector.py) | CloudTrail events — privilege escalation, suspicious API calls, unusual access patterns, unauthorized activity |
| [ec2_sg_auditor.py](cloud/ec2_sg_auditor.py) | EC2 security groups — overly permissive ingress rules (0.0.0.0/0), sensitive port exposure, orphaned groups |

## DevOps (`devops/`)

| Script | What it checks |
|---|---|
| [k8s_resource_audit.py](devops/k8s_resource_audit.py) | Kubernetes workloads — missing CPU/memory limits, missing liveness/readiness probes, crash-looping pods, empty services |
| [terraform_drift_detector.py](devops/terraform_drift_detector.py) | Terraform plan output — categorizes infrastructure drift by severity (CRITICAL / HIGH / MEDIUM / LOW), JSON output for CI/CD gates |
| [dockerfile_security_scanner.py](devops/dockerfile_security_scanner.py) | Dockerfiles — running as root, unpinned base images, hardcoded secrets, `curl \| bash` patterns, unpinned packages, missing HEALTHCHECK |
| [github_actions_audit.py](devops/github_actions_audit.py) | GitHub Actions workflows — dangerous triggers, unpinned actions, script injection vectors, hardcoded secrets, overly permissive token scopes |

## Security (`security/`)

| Script | What it checks |
|---|---|
| [linux_hardening_audit.sh](security/linux_hardening_audit.sh) | Linux system — SSH config, firewall status, SUID binaries, world-writable files, empty passwords, sudo logging, open ports |
| [owasp_headers_check.py](security/owasp_headers_check.py) | HTTP security headers — HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, server version leak |
| [ssl_cert_auditor.py](security/ssl_cert_auditor.py) | SSL/TLS — certificate expiry, weak cipher suites, deprecated protocol versions (SSLv3, TLS 1.0/1.1) |
| [secrets_scanner.py](security/secrets_scanner.py) | Filesystem — 24 hardcoded-secret patterns (AWS, GCP, Azure, GitHub, Stripe, SendGrid, JWT, DB connection strings, private keys); JSON output; `--fail-on-findings` flag for CI |

---

## Usage

### Cloud — AWS audits

```bash
pip install boto3
aws configure   # or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY

python cloud/aws_s3_audit.py
python cloud/aws_iam_audit.py
python cloud/ec2_sg_auditor.py
python cloud/cloudtrail_threat_detector.py
```

### DevOps — Kubernetes audit

```bash
pip install kubernetes
python devops/k8s_resource_audit.py
```

### DevOps — Terraform drift detection

```bash
terraform plan -out=tfplan
terraform show -json tfplan | python devops/terraform_drift_detector.py
```

### DevOps — Dockerfile scanner

```bash
python devops/dockerfile_security_scanner.py path/to/Dockerfile
```

### DevOps — GitHub Actions audit

```bash
pip install pyyaml
python devops/github_actions_audit.py .github/workflows/
```

### Security — Linux hardening

```bash
sudo bash security/linux_hardening_audit.sh
sudo bash security/linux_hardening_audit.sh --json   # machine-readable output
```

### Security — OWASP headers check

```bash
pip install requests
python security/owasp_headers_check.py https://example.com
```

### Security — SSL/TLS audit

```bash
python security/ssl_cert_auditor.py example.com
```

### Security — Secrets scanner

```bash
python security/secrets_scanner.py /path/to/scan
python security/secrets_scanner.py /path/to/scan --fail-on-findings   # exit 1 if secrets found (CI use)
python security/secrets_scanner.py /path/to/scan --json               # JSON output
```

---

## Contributing

PRs welcome. Each script should be standalone and runnable with minimal setup. Add a docstring at the top describing what the script checks and any required dependencies.

## License

MIT
