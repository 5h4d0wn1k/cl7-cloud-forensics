> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# CL7 — Cloud Forensics Toolkit

Cloud-native forensics analyzer for post-breach evidence collection and incident analysis across
**AWS, GCP, and Azure** — log-source inventory, SHA-256 snapshot manifests with chain of custody,
MFA/credential anomaly detection, and security-group exposure checks — entirely offline on bundled
fixtures or live cloud accounts you own.

![MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/cl7-cloud-forensics)
![GitHub last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/cl7-cloud-forensics)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/cl7-cloud-forensics)

## Why

Cloud incident response is fought with evidence: what was logged, what was accessed, and what was
exposed. CL7 automates the forensics checklist — it inventories whether CloudTrail/VPC Flow/
GuardDuty/S3 logging is enabled, hashes and timestamps every listed resource into a chain-of-custody
snapshot manifest, detects missing MFA and stale keys, flags wildcard IAM policies and open security
groups, and correlates events into an incident timeline. It is an educational, cloud-forensics and
incident-response instrument that runs with zero third-party dependencies against embedded demo data
or a config fixture; live analysis of any real cloud account requires explicit written authorization
from the account owner.

## Features

- **Log source inventory** — detects CloudTrail, VPC Flow, GuardDuty, and S3 access-logging gaps.
- **Snapshot manifest** — SHA-256 hash + timestamp per resource for chain-of-custody evidence.
- **MFA / credential anomalies** — root MFA missing, stale keys, wildcard IAM policies, unknown
  AssumeRole.
- **Security group analysis** — flags SSH/DB ports open to `0.0.0.0/0`.
- **Event timeline** — correlates events with anomaly markers into a severity-scored report.
- **CI-grade exit codes** — `0` clean, `1` error, `2` CRITICAL/HIGH findings under
  `--exit-code-on-findings`.

## Quickstart

Prerequisite: Python 3 (standard library; optional `boto3` for live AWS analysis).

```bash
python3 firmware/cloud_forensics.py                     # offline demo, exit 0
python3 firmware/cloud_forensics.py --config fixtures/cloud_config.json
python3 firmware/cloud_forensics.py --config fixtures/cloud_config.json \
    --output reports/my.json
python3 firmware/cloud_forensics.py --config fixtures/cloud_config.json \
    --exit-code-on-findings; echo $?                    # 2 when findings exist
```

## Examples

- `fixtures/cloud_config.json` — bundled cloud config that exercises every detection path:
  MFA not enforced, root MFA disabled, unknown-user AssumeRole, open SSH/DB security groups.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Project structure

- `firmware/cloud_forensics.py` — the forensics engine and CLI.
- `fixtures/` — offline cloud-config fixtures.
- `tests/` — stdlib unittest suite.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep the tool offline-first and dependency-free.

## License

MIT — see [LICENSE](LICENSE).