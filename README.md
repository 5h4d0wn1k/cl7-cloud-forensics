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
# Run offline demo with embedded sample data
python3 cloud_forensics.py

# Analyze a specific cloud config
python3 cloud_forensics.py --config cloud_config.json

# Export findings to JSON
python3 cloud_forensics.py --config cloud_config.json --output report.json
```

## Example Output

```
============================================================
  CL7 — Cloud Forensics Toolkit
============================================================
  Mode: Offline Demo (no credentials)

============================================================
  LOG SOURCE INVENTORY
============================================================
    [!!] MISSING CloudTrail Log Validation: DISABLED
    [!!] MISSING VPC Flow Logs: DISABLED
    [OK] CloudTrail: ENABLED

  Coverage: 2/7 log sources active
  WARNING: 5 log source(s) missing — blind spots exist

============================================================
  MFA & CREDENTIAL ANOMALY DETECTION
============================================================
  [!!] CRITICAL: MFA not enforced for IAM users
  [!!] CRITICAL: Root account MFA disabled
  [!!] HIGH: Over-privileged policy 'FullAccess' on user 'admin-user'

============================================================
  EVENT CORRELATION TIMELINE
============================================================
  2026-03-01T02:10:00Z  [!!!] cloudtrail   AssumeRole    user=unknown   ip=45.33.32.156   AdminRole [UNKNOWN_USER, SUSPICIOUS_IP]

  Total events: 9
  Suspicious events: 5
```

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
