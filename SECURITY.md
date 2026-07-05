# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub Security Advisories](https://github.com/Big-Comfy/deadair/security/advisories/new)
("Report a vulnerability"). Do not open public issues for security reports.

You can expect an acknowledgement within 7 days. Coordinated disclosure preferred; we'll credit
reporters in release notes unless you ask otherwise.

## Scope notes

deadair is a read-only monitor that holds SIEM credentials and produces reports that map
detection blind spots. Reports that are especially relevant:

- anything that lets the deadair credential write to the monitored SIEM, or that requires more
  than the documented least-privilege role (docs/credentials/)
- `--redact` output leaking source, rule, or pattern names
- report/state files created with permissions wider than 0600
- the exporter serving beyond its bind address, or any undisclosed outbound connection
  (deadair must never phone home)

## Supported versions

Only the latest release receives fixes.
