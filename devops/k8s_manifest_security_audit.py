#!/usr/bin/env python3
"""
k8s_manifest_security_audit.py — Static security auditor for Kubernetes manifests.

Purpose
    Scan Kubernetes YAML manifests for pod/container security misconfigurations
    before they ever reach a cluster. Checks are aligned with the Kubernetes
    Pod Security Standards (Baseline/Restricted) and the CIS Kubernetes
    Benchmark workload controls — the same class of findings tools like
    kube-score, Polaris, and Checkov flag, but in a single dependency-light
    script you can drop into any CI pipeline.

    It audits the pod template of every workload kind (Pod, Deployment,
    DaemonSet, StatefulSet, ReplicaSet, Job, CronJob) plus init containers,
    and reports:
      - privileged containers
      - allowPrivilegeEscalation not disabled
      - containers running as root (runAsNonRoot unset / runAsUser 0)
      - host namespace sharing (hostNetwork / hostPID / hostIPC)
      - hostPath volume mounts (node filesystem escape)
      - dangerous added Linux capabilities / not dropping ALL
      - writable root filesystem (readOnlyRootFilesystem unset)
      - service-account token auto-mounted when not needed
      - mutable image tags (:latest or no tag — no reproducibility/pinning)

Usage
    python3 k8s_manifest_security_audit.py <file-or-dir> [<file-or-dir> ...]
    python3 k8s_manifest_security_audit.py ./manifests --json
    python3 k8s_manifest_security_audit.py deploy.yaml --fail-on-findings --min-severity HIGH

    Exit code is 0 by default. With --fail-on-findings it returns 1 when any
    finding at or above --min-severity is present, so it can gate a pipeline.

Dependencies
    Python 3.7+ and PyYAML (`pip install pyyaml`). Standard library otherwise.

Author
    ashvinctrl — https://github.com/ashvinctrl/cloud-security-scripts
"""
import argparse
import json
import os
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "error: PyYAML is required. Install it with `pip install pyyaml`.\n"
    )
    sys.exit(2)


SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Workload kinds and the dotted path to their embedded pod spec.
POD_SPEC_PATHS = {
    "Pod": "spec",
    "Deployment": "spec.template.spec",
    "DaemonSet": "spec.template.spec",
    "StatefulSet": "spec.template.spec",
    "ReplicaSet": "spec.template.spec",
    "ReplicationController": "spec.template.spec",
    "Job": "spec.template.spec",
    "CronJob": "spec.jobTemplate.spec.template.spec",
}

# Capabilities that grant host-level power; adding any is a red flag.
DANGEROUS_CAPS = {
    "ALL", "SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE", "SYS_MODULE",
    "SYS_BOOT", "SYS_TIME", "DAC_READ_SEARCH", "DAC_OVERRIDE", "SETUID",
    "SETGID", "SYS_CHROOT", "MKNOD", "AUDIT_WRITE", "BPF", "PERFMON",
}


def _dig(obj, dotted):
    """Walk a dotted path (spec.template.spec) returning {} if any hop is absent."""
    cur = obj
    for key in dotted.split("."):
        if not isinstance(cur, dict):
            return {}
        cur = cur.get(key)
        if cur is None:
            return {}
    return cur if isinstance(cur, dict) else {}


def _image_tag(image):
    """Return the tag portion of an image ref, or None when untagged/undigested."""
    if not image:
        return None
    # Strip a digest first (image@sha256:...), which is a valid pin.
    if "@" in image:
        return "@digest"
    # A ':' after the last '/' is a tag; a ':' inside the host:port is not.
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        return last.split(":", 1)[1]
    return None


class Finding:
    __slots__ = ("severity", "kind", "name", "container", "check", "message", "remediation")

    def __init__(self, severity, kind, name, container, check, message, remediation):
        self.severity = severity
        self.kind = kind
        self.name = name
        self.container = container
        self.check = check
        self.message = message
        self.remediation = remediation

    def as_dict(self):
        return {
            "severity": self.severity,
            "kind": self.kind,
            "resource": self.name,
            "container": self.container,
            "check": self.check,
            "message": self.message,
            "remediation": self.remediation,
        }


def _sec_ctx(obj):
    ctx = obj.get("securityContext")
    return ctx if isinstance(ctx, dict) else {}


def audit_pod_spec(kind, name, pod_spec, findings):
    """Append findings for one pod spec (pod-level + every container)."""
    pod_ctx = _sec_ctx(pod_spec)

    def add(sev, container, check, message, fix):
        findings.append(Finding(sev, kind, name, container, check, message, fix))

    # ---- Pod-level namespace / mount checks ----
    for field, sev in (("hostNetwork", "HIGH"), ("hostPID", "HIGH"), ("hostIPC", "HIGH")):
        if pod_spec.get(field) is True:
            add(sev, "-", field,
                f"{field} is enabled, sharing the node's namespace with the pod.",
                f"Remove {field}: true unless a node-level agent genuinely requires it.")

    for vol in pod_spec.get("volumes") or []:
        if isinstance(vol, dict) and "hostPath" in vol:
            path = (vol.get("hostPath") or {}).get("path", "?")
            add("HIGH", "-", "hostPath",
                f"volume '{vol.get('name', '?')}' mounts hostPath {path} from the node.",
                "Replace hostPath with a PVC, emptyDir, or configMap; hostPath allows node escape.")

    if pod_spec.get("automountServiceAccountToken") is not False:
        add("LOW", "-", "automountServiceAccountToken",
            "the default service-account token is auto-mounted into the pod.",
            "Set automountServiceAccountToken: false unless the workload calls the Kubernetes API.")

    # ---- Container-level checks (regular + init containers) ----
    containers = list(pod_spec.get("containers") or [])
    inits = [(c, True) for c in (pod_spec.get("initContainers") or [])]
    for c, is_init in [(c, False) for c in containers] + inits:
        if not isinstance(c, dict):
            continue
        cname = c.get("name", "?") + (" (init)" if is_init else "")
        ctx = _sec_ctx(c)

        if ctx.get("privileged") is True:
            add("CRITICAL", cname, "privileged",
                "container runs in privileged mode (full host device + kernel access).",
                "Remove privileged: true; grant only the specific capabilities actually needed.")

        # allowPrivilegeEscalation defaults to true when unset.
        if ctx.get("allowPrivilegeEscalation") is not False:
            add("HIGH", cname, "allowPrivilegeEscalation",
                "allowPrivilegeEscalation is not disabled (a process can gain more privileges than its parent).",
                "Set securityContext.allowPrivilegeEscalation: false.")

        # Effective run-as-root: pod-level runAsNonRoot can satisfy this.
        run_as_non_root = ctx.get("runAsNonRoot")
        if run_as_non_root is None:
            run_as_non_root = pod_ctx.get("runAsNonRoot")
        run_as_user = ctx.get("runAsUser", pod_ctx.get("runAsUser"))
        if run_as_user == 0:
            add("HIGH", cname, "runAsUser",
                "container explicitly sets runAsUser: 0 (root).",
                "Run as a non-zero UID and set runAsNonRoot: true.")
        elif run_as_non_root is not True:
            add("MEDIUM", cname, "runAsNonRoot",
                "container may run as root (runAsNonRoot is not set to true).",
                "Set securityContext.runAsNonRoot: true (pod or container level).")

        caps = ctx.get("capabilities") or {}
        added = {str(x).upper().lstrip("+") for x in (caps.get("add") or [])}
        dropped = {str(x).upper() for x in (caps.get("drop") or [])}
        risky = added & DANGEROUS_CAPS
        if risky:
            add("HIGH", cname, "capabilities.add",
                f"container adds dangerous capabilities: {', '.join(sorted(risky))}.",
                "Drop these capabilities; add back only the minimal set the app requires.")
        if "ALL" not in dropped:
            add("LOW", cname, "capabilities.drop",
                "container does not drop ALL capabilities as a baseline.",
                "Set capabilities.drop: [\"ALL\"], then add back only what is needed.")

        if ctx.get("readOnlyRootFilesystem") is not True:
            add("LOW", cname, "readOnlyRootFilesystem",
                "root filesystem is writable (readOnlyRootFilesystem not true).",
                "Set readOnlyRootFilesystem: true and mount an emptyDir for any writable paths.")

        tag = _image_tag(c.get("image"))
        if tag is None:
            add("MEDIUM", cname, "image",
                f"image '{c.get('image', '?')}' has no tag (defaults to :latest).",
                "Pin the image to an explicit version tag or, better, a digest.")
        elif tag == "latest":
            add("MEDIUM", cname, "image",
                f"image '{c.get('image', '?')}' uses the mutable :latest tag.",
                "Pin to an immutable version tag or a @sha256 digest for reproducible deploys.")


def iter_yaml_docs(path):
    """Yield (source_path, document) for every YAML doc under a file or dir."""
    files = []
    if os.path.isdir(path):
        for root, _, names in os.walk(path):
            for n in names:
                if n.endswith((".yaml", ".yml")):
                    files.append(os.path.join(root, n))
    else:
        files.append(path)

    for fpath in sorted(files):
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                for doc in yaml.safe_load_all(fh):
                    if isinstance(doc, dict):
                        yield fpath, doc
        except (yaml.YAMLError, OSError) as exc:
            sys.stderr.write(f"warning: skipping {fpath}: {exc}\n")


def audit_paths(paths):
    findings = []
    scanned = 0
    for path in paths:
        for _fpath, doc in iter_yaml_docs(path):
            kind = doc.get("kind")
            spec_path = POD_SPEC_PATHS.get(kind)
            if not spec_path:
                continue
            scanned += 1
            name = _dig(doc, "metadata").get("name", "<unnamed>")
            pod_spec = _dig(doc, spec_path)
            if pod_spec:
                audit_pod_spec(kind, name, pod_spec, findings)
    return findings, scanned


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit Kubernetes manifests for pod/container security misconfigurations."
    )
    parser.add_argument("paths", nargs="+", help="YAML files or directories to scan")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument("--min-severity", default="LOW",
                        choices=list(SEVERITY_ORDER), help="lowest severity to report")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="exit 1 if any finding at/above --min-severity is present (for CI)")
    args = parser.parse_args(argv)

    threshold = SEVERITY_ORDER[args.min_severity]
    findings, scanned = audit_paths(args.paths)
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= threshold]
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.kind, f.name))

    if args.json:
        print(json.dumps({
            "workloads_scanned": scanned,
            "findings_count": len(findings),
            "findings": [f.as_dict() for f in findings],
        }, indent=2))
    else:
        print(f"Scanned {scanned} workload(s); found {len(findings)} issue(s) "
              f"at or above {args.min_severity}.\n")
        if not findings:
            print("No issues found.")
        for f in findings:
            print(f"[{f.severity:8}] {f.kind}/{f.name} :: {f.container} :: {f.check}")
            print(f"           {f.message}")
            print(f"           fix: {f.remediation}\n")

    if args.fail_on_findings and findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
