# cloud-security-scripts

Practical security and DevOps automation scripts — one script a day across Cloud, DevOps, and Cybersecurity.

## Structure

```
cloud/       AWS, Azure, GCP security audit scripts
devops/      Kubernetes, Docker, CI/CD tooling
security/    Linux hardening, recon, and CTF tools
```

## Scripts

### Cloud (`cloud/`)

| Script | Description |
|--------|-------------|
| [aws_s3_audit.py](cloud/aws_s3_audit.py) | Audits all S3 buckets for public access, encryption, versioning, logging, and ACL misconfigs |

### DevOps (`devops/`)

| Script | Description |
|--------|-------------|
| [k8s_resource_audit.py](devops/k8s_resource_audit.py) | Audits Kubernetes workloads for missing resource limits, liveness/readiness probes, crash loops, and empty services |

### Security (`security/`)

| Script | Description |
|--------|-------------|
| [linux_hardening_audit.sh](security/linux_hardening_audit.sh) | Audits a Linux system for SSH misconfigs, firewall status, SUID binaries, world-writable files, empty passwords, sudo logging, and open ports |

## Usage

**Cloud — AWS S3 Audit**
```bash
pip install boto3
aws configure
python cloud/aws_s3_audit.py
```

**DevOps — Kubernetes Audit**
```bash
pip install kubernetes
python devops/k8s_resource_audit.py
```

**Security — Linux Hardening Audit**
```bash
sudo bash security/linux_hardening_audit.sh
# JSON output:
sudo bash security/linux_hardening_audit.sh --json
```

## Contributing

PRs welcome. Each script should be standalone and runnable with minimal setup.
