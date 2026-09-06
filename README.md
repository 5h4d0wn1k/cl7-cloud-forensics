# CL7 — Cloud Forensics Toolkit

Post-breach cloud evidence gathering, incident analysis, and forensic timeline reconstruction.

## Overview

This project implements a cloud forensics toolkit that:
- Inventories cloud log sources and detects missing/disabled logging
- Generates snapshot manifests with SHA-256 hashes and timestamps for listed resources
- Detects MFA/credential anomalies in cloud configs (missing MFA, over-privileged policies, stale keys)
- Correlates events into an incident timeline with anomaly flagging
- Flags security group misconfigurations (open SSH/DB ports to 0.0.0.0/0)
- Produces a forensic summary report with severity-scored findings

## Features

- **Log Source Inventory**: Detect CloudTrail, VPC Flow, GuardDuty, S3 access logging gaps
- **Snapshot Manifest**: Hash + timestamp every resource for chain-of-custody evidence
- **MFA/Credential Anomalies**: Root MFA missing, stale keys, wildcard IAM policies, unknown AssumeRole
- **Security Group Analysis**: Detect SSH/DB ports open to the internet
- **Event Timeline**: Correlate CloudTrail/VPC/GuardDuty events with anomaly markers
- **Forensic Report**: Severity-scored findings summary

## Dependencies

**None** — uses only Python standard library. Optional `boto3` / `google-cloud` for live cloud analysis (gracefully degrades to offline demo).

## Installation

```bash
# No installation required — standard library only
python3 cloud_forensics.py

# Optional: install boto3 for live AWS analysis
pip install boto3
```

## Usage

```bash
# Run offline demo with embedded sample data (no config, exit 0)
python3 firmware/cloud_forensics.py

# Analyze the bundled cloud config fixture (offline)
python3 firmware/cloud_forensics.py --config fixtures/cloud_config.json

# Export findings to JSON (defaults to reports/cl7-report.json)
python3 firmware/cloud_forensics.py --config fixtures/cloud_config.json --output reports/my.json

# CI-friendly: exit 2 when CRITICAL/HIGH findings exist
python3 firmware/cloud_forensics.py --config fixtures/cloud_config.json --exit-code-on-findings; echo $?
```

## Exit Codes

- `0` — completed cleanly (or demo finished without explicit CRITICAL/HIGH gate)
- `1` — error (unreadable/missing config)
- `2` — CRITICAL/HIGH findings present with `--exit-code-on-findings`

## Live Lab Test Plan

Runs entirely offline on the bundled fixture `fixtures/cloud_config.json` — no cloud account, no credentials, no network.

1. **Demo**: `python3 firmware/cloud_forensics.py` — no-arg mode uses embedded demo data and exits `0`.
2. **Fixture run**: `python3 firmware/cloud_forensics.py --config fixtures/cloud_config.json` — produce CRITICAL findings: MFA not enforced, root MFA disabled, unknown-user AssumeRole, open SSH (22/3389) security groups, and HIGH findings: console MFA missing, over-privileged wildcard policy, open DB (3306) port.
3. **JSON report**: verify `reports/cl7-report.json` has `finding_count > 0`, `critical_high_count > 0`, and a `snapshot_manifest` + `timeline`.
4. **CI exit code**: `--exit-code-on-findings` returns `2`.
5. **Unit tests**: `python3 -m unittest discover -s tests -v` — all pass.

## Metrics

- Real detection paths exercised offline: log-source inventory, SHA-256 snapshot manifest, MFA/credential anomalies, security-group port exposure, event-correlation timeline
- 9 unit tests cover the engine on the fixture and embedded demo
- Every finding carries `category`, `severity`, and `detail`
- Exit-code contract: `0` clean / `1` error / `2` findings (with `--exit-code-on-findings`)
- Zero third-party dependencies; `--demo`/`--config` require no cloud access

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the cloud account owner before using this tool
- Unauthorized access to cloud environments is illegal under federal and state laws
- This tool should ONLY be used on cloud accounts you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **AWS/GCP/Azure Acceptable Use Policies**: Unauthorized probing violates cloud provider ToS
- **State Laws**: Many states have additional computer crime statutes
- **GDPR/CCPA**: Cloud data access may be subject to privacy regulations

### Acceptable Use
- Testing security of your own cloud environments
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Accessing cloud accounts you do not own
- Modifying or deleting cloud resources without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
