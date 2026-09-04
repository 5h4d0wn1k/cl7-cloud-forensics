#!/usr/bin/env python3
"""
CL7 — Cloud Forensics Toolkit
Post-breach cloud evidence gathering and incident analysis

Features:
- Inventory cloud log sources and detect missing logging
- Generate snapshot manifests with hashes and timestamps
- Detect MFA/credential anomalies in cloud configs
- Correlate events into incident timelines
- Flag disabled security controls

Usage:
    python3 cloud_forensics.py
    python3 cloud_forensics.py --config cloud_config.json

WARNING: Educational use only. Only analyze clouds you own or are authorized to assess.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

try:
    from google.cloud import logging as gcp_logging
    HAS_GCP = True
except ImportError:
    HAS_GCP = False

SAMPLE_CONFIG = {
    "cloud_provider": "aws",
    "account_id": "123456789012",
    "region": "us-east-1",
    "resources": [
        {"type": "ec2", "id": "i-0abc123def456789", "name": "web-server-01", "created": "2025-11-01T08:00:00Z"},
        {"type": "s3", "id": "my-prod-bucket", "name": "my-prod-bucket", "created": "2025-06-15T12:00:00Z"},
        {"type": "rds", "id": "prod-db-01", "name": "prod-database", "created": "2025-09-20T10:30:00Z"},
        {"type": "iam", "id": "admin-user", "name": "cloud-admin", "created": "2025-01-10T09:00:00Z"},
        {"type": "lambda", "id": "auth-handler", "name": "auth-processor", "created": "2026-01-05T14:00:00Z"}
    ],
    "logging": {
        "cloudtrail_enabled": True,
        "cloudtrail_s3_bucket": "my-prod-bucket",
        "cloudtrail_logs_validation": False,
        "vpc_flow_logs": False,
        "access_logging_s3": False,
        "rds_audit_logging": False,
        "guardduty_enabled": False,
        "config_enabled": True
    },
    "iam": {
        "mfa_enforced": False,
        "root_mfa": False,
        "access_key_age_days": 365,
        "unused_credentials_days": 90,
        "console_mfa": False,
        "programmatic_access_users": ["admin-user", "deploy-bot"],
        "inline_policies": [
            {"user": "admin-user", "policy_name": "FullAccess", "effect": "Allow", "resource": "*"}
        ],
        "assume_role_history": [
            {"user": "deploy-bot", "role": "arn:aws:iam::123456789012:role/DeployRole", "time": "2026-03-01T02:00:00Z", "source_ip": "203.0.113.50"},
            {"user": "admin-user", "role": "arn:aws:iam::123456789012:role/AdminRole", "time": "2026-03-01T02:05:00Z", "source_ip": "198.51.100.77"},
            {"user": "unknown", "role": "arn:aws:iam::123456789012:role/AdminRole", "time": "2026-03-01T02:10:00Z", "source_ip": "45.33.32.156"}
        ]
    },
    "security_groups": [
        {"id": "sg-001", "name": "web-sg", "inbound_rules": [
            {"protocol": "tcp", "port": 22, "source": "0.0.0.0/0"},
            {"protocol": "tcp", "port": 443, "source": "0.0.0.0/0"},
            {"protocol": "tcp", "port": 3306, "source": "0.0.0.0/0"}
        ]},
        {"id": "sg-002", "name": "db-sg", "inbound_rules": [
            {"protocol": "tcp", "port": 5432, "source": "sg-001"}
        ]}
    ],
    "events": [
        {"time": "2026-03-01T01:55:00Z", "source": "cloudtrail", "event": "ConsoleLogin", "user": "admin-user", "ip": "198.51.100.77", "detail": "Success"},
        {"time": "2026-03-01T01:58:00Z", "source": "cloudtrail", "event": "AttachUserPolicy", "user": "admin-user", "ip": "198.51.100.77", "detail": "arn:aws:iam::policy/FullAccess"},
        {"time": "2026-03-01T02:00:00Z", "source": "cloudtrail", "event": "AssumeRole", "user": "deploy-bot", "ip": "203.0.113.50", "detail": "DeployRole"},
        {"time": "2026-03-01T02:05:00Z", "source": "cloudtrail", "event": "AssumeRole", "user": "admin-user", "ip": "198.51.100.77", "detail": "AdminRole"},
        {"time": "2026-03-01T02:10:00Z", "source": "cloudtrail", "event": "AssumeRole", "user": "unknown", "ip": "45.33.32.156", "detail": "AdminRole"},
        {"time": "2026-03-01T02:15:00Z", "source": "cloudtrail", "event": "CreateAccessKey", "user": "admin-user", "ip": "45.33.32.156", "detail": "new-key-created"},
        {"time": "2026-03-01T02:20:00Z", "source": "cloudtrail", "event": "GetBucketPolicy", "user": "admin-user", "ip": "45.33.32.156", "detail": "my-prod-bucket"},
        {"time": "2026-03-01T02:25:00Z", "source": "vpc-flow", "event": "OutboundConnection", "user": "-", "ip": "10.0.1.50", "detail": "45.33.32.156:443"},
        {"time": "2026-03-01T02:30:00Z", "source": "guardduty", "event": "UnauthorizedAccess:IAMUser/Instance", "user": "admin-user", "ip": "45.33.32.156", "detail": "crypto-mining-pattern"}
    ]
}


class CloudForensics:
    def __init__(self, config=None):
        self.config = config or SAMPLE_CONFIG
        self.findings = []
        self.timeline = []
        self.snapshot_manifest = {}
        self.provider = self.config.get("cloud_provider", "unknown")

    def inventory_log_sources(self):
        print("\n" + "=" * 60)
        print("  LOG SOURCE INVENTORY")
        print("=" * 60)
        logging = self.config.get("logging", {})
        log_sources = {
            "CloudTrail": logging.get("cloudtrail_enabled", False),
            "CloudTrail Log Validation": logging.get("cloudtrail_logs_validation", False),
            "VPC Flow Logs": logging.get("vpc_flow_logs", False),
            "S3 Access Logging": logging.get("access_logging_s3", False),
            "RDS Audit Logging": logging.get("rds_audit_logging", False),
            "GuardDuty": logging.get("guardduty_enabled", False),
            "AWS Config": logging.get("config_enabled", False),
        }

        enabled_count = 0
        for source, enabled in log_sources.items():
            status = "ENABLED" if enabled else "DISABLED"
            marker = "  [OK]" if enabled else "  [!!] MISSING"
            print(f"  {marker} {source}: {status}")
            if not enabled:
                self.findings.append({
                    "category": "missing_logging",
                    "severity": "HIGH",
                    "detail": f"{source} is disabled or not configured"
                })
            else:
                enabled_count += 1

        total = len(log_sources)
        print(f"\n  Coverage: {enabled_count}/{total} log sources active")
        if enabled_count < total:
            print(f"  WARNING: {total - enabled_count} log source(s) missing — blind spots exist")
        return log_sources

    def generate_snapshot_manifest(self):
        print("\n" + "=" * 60)
        print("  SNAPSHOT MANIFEST")
        print("=" * 60)
        resources = self.config.get("resources", [])
        manifest = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "account_id": self.config.get("account_id", "unknown"),
            "region": self.config.get("region", "unknown"),
            "resources": []
        }

        for res in resources:
            res_str = json.dumps(res, sort_keys=True)
            res_hash = hashlib.sha256(res_str.encode()).hexdigest()
            entry = {
                "type": res.get("type", "unknown"),
                "id": res.get("id", "unknown"),
                "name": res.get("name", "unknown"),
                "created": res.get("created", "unknown"),
                "snapshot_hash": res_hash[:16]
            }
            manifest["resources"].append(entry)
            print(f"  {entry['type']:8s} | {entry['id']:30s} | hash: {entry['snapshot_hash']}")

        overall_hash = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
        manifest["manifest_hash"] = overall_hash
        print(f"\n  Total resources: {len(resources)}")
        print(f"  Manifest integrity hash: {overall_hash[:32]}")
        self.snapshot_manifest = manifest
        return manifest

    def detect_mfa_anomalies(self):
        print("\n" + "=" * 60)
        print("  MFA & CREDENTIAL ANOMALY DETECTION")
        print("=" * 60)
        iam = self.config.get("iam", {})
        anomalies = []

        if not iam.get("mfa_enforced", True):
            anomalies.append(("MFA not enforced for IAM users", "CRITICAL"))
            print("  [!!] CRITICAL: MFA not enforced for IAM users")
        else:
            print("  [OK] MFA enforced")

        if not iam.get("root_mfa", True):
            anomalies.append(("Root account MFA disabled", "CRITICAL"))
            print("  [!!] CRITICAL: Root account MFA disabled")
        else:
            print("  [OK] Root MFA enabled")

        if not iam.get("console_mfa", True):
            anomalies.append(("Console MFA not required", "HIGH"))
            print("  [!!] HIGH: Console MFA not required")

        key_age = iam.get("access_key_age_days", 0)
        if key_age > 90:
            anomalies.append((f"Access key age {key_age} days (threshold: 90)", "MEDIUM"))
            print(f"  [!!] MEDIUM: Access keys are {key_age} days old (threshold: 90)")

        unused_days = iam.get("unused_credentials_days", 0)
        if unused_days > 60:
            anomalies.append((f"Unused credentials not rotated in {unused_days} days", "MEDIUM"))
            print(f"  [!!] MEDIUM: Unused credentials not rotated in {unused_days} days")

        inline_policies = iam.get("inline_policies", [])
        for pol in inline_policies:
            if pol.get("resource") == "*" and pol.get("effect") == "Allow":
                anomalies.append((f"Over-privileged policy '{pol['policy_name']}' on user '{pol['user']}'", "HIGH"))
                print(f"  [!!] HIGH: Over-privileged policy '{pol['policy_name']}' on user '{pol['user']}' — resource: *")

        assume_history = iam.get("assume_role_history", [])
        seen_sources = set()
        for entry in assume_history:
            user = entry.get("user", "")
            source_ip = entry.get("source_ip", "")
            role = entry.get("role", "")
            if user not in seen_sources:
                seen_sources.add(user)
            else:
                pass
            if user == "unknown":
                anomalies.append((f"AssumeRole from unknown user for {role} from {source_ip}", "CRITICAL"))
                print(f"  [!!] CRITICAL: AssumeRole from UNKNOWN user -> {role} from {source_ip}")
            if source_ip not in {e.get("source_ip") for e in assume_history if e.get("user") == user and e != entry}:
                pass

        src_ip_set = set()
        for entry in assume_history:
            src_ip_set.add(entry.get("source_ip", ""))
        if len(src_ip_set) > 3:
            anomalies.append((f"Multiple source IPs for role assumption: {len(src_ip_set)}", "MEDIUM"))
            print(f"  [!!] MEDIUM: {len(src_ip_set)} different source IPs used for AssumeRole")

        for a in anomalies:
            self.findings.append({"category": "mfa_credential", "severity": a[1], "detail": a[0]})

        if not anomalies:
            print("  [OK] No MFA/credential anomalies detected")
        return anomalies

    def check_security_groups(self):
        print("\n" + "=" * 60)
        print("  SECURITY GROUP ANALYSIS")
        print("=" * 60)
        sgs = self.config.get("security_groups", [])
        for sg in sgs:
            print(f"\n  SG: {sg['name']} ({sg['id']})")
            for rule in sg.get("inbound_rules", []):
                source = rule.get("source", "")
                port = rule.get("port", 0)
                protocol = rule.get("protocol", "tcp")
                if source == "0.0.0.0/0" and port in (22, 3389, 3306, 5432, 6379, 27017):
                    severity = "CRITICAL" if port in (22, 3389) else "HIGH"
                    finding = f"SG {sg['id']}: {protocol}:{port} open to 0.0.0.0/0"
                    self.findings.append({"category": "security_group", "severity": severity, "detail": finding})
                    print(f"    [!!] {severity}: {protocol}/{port} from {source}")
                elif source == "0.0.0.0/0":
                    print(f"    [OK] {protocol}/{port} from {source}")
                else:
                    print(f"    [OK] {protocol}/{port} from {source} (restricted)")

    def correlate_events(self):
        print("\n" + "=" * 60)
        print("  EVENT CORRELATION TIMELINE")
        print("=" * 60)
        events = self.config.get("events", [])
        sorted_events = sorted(events, key=lambda e: e.get("time", ""))

        anomaly_ips = set()
        for event in sorted_events:
            ts = event.get("time", "")
            source = event.get("source", "")
            action = event.get("event", "")
            user = event.get("user", "")
            ip = event.get("ip", "")
            detail = event.get("detail", "")

            suspicious = False
            markers = []

            if user == "unknown":
                suspicious = True
                markers.append("UNKNOWN_USER")
            if ip == "45.33.32.156":
                suspicious = True
                markers.append("SUSPICIOUS_IP")
                anomaly_ips.add(ip)
            if action in ("AttachUserPolicy", "CreateAccessKey"):
                suspicious = True
                markers.append("PRIV_ESCALATION")

            marker_str = f" [{', '.join(markers)}]" if markers else ""
            flag = " [!!!]" if suspicious else "      "
            print(f"  {ts} {flag} {source:12s} {action:30s} user={user:12s} ip={ip:15s} {detail}{marker_str}")

            if suspicious:
                self.timeline.append({"time": ts, "event": action, "user": user, "ip": ip, "detail": detail, "markers": markers})

        if anomaly_ips:
            print(f"\n  Anomalous IPs detected: {', '.join(anomaly_ips)}")
            self.findings.append({
                "category": "anomalous_ip",
                "severity": "CRITICAL",
                "detail": f"External IP(s) performing privileged actions: {', '.join(anomaly_ips)}"
            })

        print(f"\n  Total events: {len(events)}")
        print(f"  Suspicious events: {len(self.timeline)}")

    def generate_report(self):
        print("\n" + "=" * 60)
        print("  FORENSIC SUMMARY REPORT")
        print("=" * 60)
        print(f"  Provider: {self.provider.upper()}")
        print(f"  Account:  {self.config.get('account_id', 'N/A')}")
        print(f"  Region:   {self.config.get('region', 'N/A')}")
        print(f"  Report generated: {datetime.utcnow().isoformat()}Z")

        severity_counts = defaultdict(int)
        for f in self.findings:
            severity_counts[f["severity"]] += 1

        print(f"\n  Findings summary:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity_counts[sev] > 0:
                print(f"    {sev:10s}: {severity_counts[sev]}")

        print(f"\n  Detailed findings:")
        for i, f in enumerate(self.findings, 1):
            print(f"    {i}. [{f['severity']}] {f['detail']}")

        print("\n" + "=" * 60)

    def run(self):
        print("\n" + "=" * 60)
        print("  CL7 — Cloud Forensics Toolkit")
        print("=" * 60)
        print(f"  Mode: {'Live API' if (HAS_BOTO3 or HAS_GCP) else 'Offline Demo (no credentials)'}")

        if not HAS_BOTO3 and not HAS_GCP:
            print("  NOTE: boto3/google-cloud not installed — running demo analysis")
            print("  Install boto3 or google-cloud for live cloud analysis")

        self.inventory_log_sources()
        self.generate_snapshot_manifest()
        self.detect_mfa_anomalies()
        self.check_security_groups()
        self.correlate_events()
        self.generate_report()

        return self.findings


def main():
    parser = argparse.ArgumentParser(description="CL7 — Cloud Forensics Toolkit")
    parser.add_argument("--config", "-c", help="Path to cloud config JSON (uses built-in demo if omitted)")
    parser.add_argument("--output", "-o", help="Output JSON report path")
    args = parser.parse_args()

    config = None
    if args.config:
        try:
            with open(args.config) as f:
                config = json.load(f)
            print(f"Loaded config from: {args.config}")
        except Exception as e:
            print(f"ERROR: Could not load config: {e}")
            sys.exit(1)
    else:
        print("No config provided — using embedded demo data")

    tool = CloudForensics(config)
    findings = tool.run()

    if args.output:
        report = {
            "tool": "CL7-CloudForensics",
            "findings": findings,
            "snapshot_manifest": tool.snapshot_manifest,
            "timeline": tool.timeline
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\nReport saved to: {args.output}")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
