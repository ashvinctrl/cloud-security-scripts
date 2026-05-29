#!/usr/bin/env python3
"""
k8s_resource_audit.py — Kubernetes cluster resource & config auditor

Checks every namespace for:
  - Pods without CPU/memory requests or limits
  - Containers missing liveness or readiness probes
  - CrashLoopBackOff / OOMKilled pods
  - Deployments with replica count = 0
  - Services with no ready endpoints

Usage:
  pip install kubernetes
  python k8s_resource_audit.py [--namespace <ns>] [--kubeconfig <path>]

Requires a valid kubeconfig (default: ~/.kube/config) or in-cluster service account.
"""

import argparse
import sys
from collections import defaultdict

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
except ImportError:
    sys.exit("Install the kubernetes client:  pip install kubernetes")


RESET = "\033[0m"
RED   = "\033[91m"
YELLOW= "\033[93m"
GREEN = "\033[92m"
BOLD  = "\033[1m"


def load_kube_config(kubeconfig: str | None) -> None:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config(config_file=kubeconfig)


def fmt(severity: str, msg: str) -> str:
    color = RED if severity == "HIGH" else YELLOW if severity == "MEDIUM" else GREEN
    return f"  {color}[{severity}]{RESET} {msg}"


def audit_pods(v1: client.CoreV1Api, namespace: str) -> list[str]:
    findings = []
    try:
        pods = v1.list_namespaced_pod(namespace).items
    except ApiException as e:
        return [fmt("HIGH", f"Cannot list pods in {namespace}: {e.reason}")]

    for pod in pods:
        name = pod.metadata.name
        phase = pod.status.phase or "Unknown"

        # Check container statuses for crash loops / OOM
        for cs in pod.status.container_statuses or []:
            state = cs.state
            if state.waiting and state.waiting.reason == "CrashLoopBackOff":
                findings.append(fmt("HIGH", f"Pod {name}/{cs.name}: CrashLoopBackOff"))
            if state.terminated and state.terminated.reason == "OOMKilled":
                findings.append(fmt("HIGH", f"Pod {name}/{cs.name}: OOMKilled"))

        # Check spec containers for resource limits and probes
        for c in pod.spec.containers:
            cname = f"{name}/{c.name}"
            res = c.resources
            if res:
                req = res.requests or {}
                lim = res.limits or {}
                if "cpu" not in req or "memory" not in req:
                    findings.append(fmt("MEDIUM", f"Container {cname}: missing resource requests (cpu/memory)"))
                if "cpu" not in lim or "memory" not in lim:
                    findings.append(fmt("MEDIUM", f"Container {cname}: missing resource limits (cpu/memory)"))
            else:
                findings.append(fmt("MEDIUM", f"Container {cname}: no resources block defined"))

            if not c.liveness_probe:
                findings.append(fmt("LOW", f"Container {cname}: no liveness probe"))
            if not c.readiness_probe:
                findings.append(fmt("LOW", f"Container {cname}: no readiness probe"))

    return findings


def audit_deployments(apps: client.AppsV1Api, namespace: str) -> list[str]:
    findings = []
    try:
        deployments = apps.list_namespaced_deployment(namespace).items
    except ApiException as e:
        return [fmt("HIGH", f"Cannot list deployments in {namespace}: {e.reason}")]

    for d in deployments:
        name = d.metadata.name
        replicas = d.spec.replicas or 0
        ready = (d.status.ready_replicas or 0)
        if replicas == 0:
            findings.append(fmt("MEDIUM", f"Deployment {name}: replicas set to 0 (scaled down)"))
        elif ready < replicas:
            findings.append(fmt("MEDIUM", f"Deployment {name}: {ready}/{replicas} replicas ready"))

    return findings


def audit_services(v1: client.CoreV1Api, namespace: str) -> list[str]:
    findings = []
    try:
        services = v1.list_namespaced_service(namespace).items
        endpoints = {
            ep.metadata.name: ep
            for ep in v1.list_namespaced_endpoints(namespace).items
        }
    except ApiException as e:
        return [fmt("HIGH", f"Cannot list services in {namespace}: {e.reason}")]

    for svc in services:
        name = svc.metadata.name
        if svc.spec.type == "ExternalName":
            continue
        ep = endpoints.get(name)
        if not ep:
            findings.append(fmt("MEDIUM", f"Service {name}: no Endpoints object found"))
            continue
        ready_addresses = []
        for subset in ep.subsets or []:
            ready_addresses.extend(subset.addresses or [])
        if not ready_addresses:
            findings.append(fmt("MEDIUM", f"Service {name}: Endpoints exist but no ready addresses"))

    return findings


def run_audit(namespaces: list[str]) -> None:
    v1   = client.CoreV1Api()
    apps = client.AppsV1Api()

    total_findings = 0
    counts: dict[str, int] = defaultdict(int)

    for ns in namespaces:
        pod_findings  = audit_pods(v1, ns)
        dep_findings  = audit_deployments(apps, ns)
        svc_findings  = audit_services(v1, ns)
        all_findings  = pod_findings + dep_findings + svc_findings

        print(f"\n{BOLD}Namespace: {ns}{RESET}")
        if not all_findings:
            print(f"  {GREEN}No issues found{RESET}")
        else:
            for f in all_findings:
                print(f)
                for sev in ("HIGH", "MEDIUM", "LOW"):
                    if f"[{sev}]" in f:
                        counts[sev] += 1
            total_findings += len(all_findings)

    print(f"\n{BOLD}Summary:{RESET}")
    print(f"  Namespaces scanned : {len(namespaces)}")
    print(f"  Total findings     : {total_findings}")
    for sev, color in [("HIGH", RED), ("MEDIUM", YELLOW), ("LOW", GREEN)]:
        print(f"  {color}[{sev}]{RESET}             : {counts[sev]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Kubernetes resource & config auditor")
    parser.add_argument("--namespace", "-n", help="Audit a single namespace (default: all)")
    parser.add_argument("--kubeconfig", "-k", help="Path to kubeconfig file")
    args = parser.parse_args()

    load_kube_config(args.kubeconfig)
    v1 = client.CoreV1Api()

    if args.namespace:
        namespaces = [args.namespace]
    else:
        try:
            namespaces = [ns.metadata.name for ns in v1.list_namespace().items]
        except ApiException as e:
            sys.exit(f"Cannot list namespaces: {e.reason}")

    print(f"{BOLD}=== Kubernetes Resource Audit ==={RESET}")
    run_audit(namespaces)


if __name__ == "__main__":
    main()
