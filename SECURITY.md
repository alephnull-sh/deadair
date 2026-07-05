# Security policy

## Report a vulnerability

Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/Big-Comfy/deadair/security/advisories/new).
Do not open a public issue for a security report.

You can expect an acknowledgement within 7 days. Coordinated disclosure is preferred. Reporters
will be credited in release notes unless they ask otherwise.

## What is in scope

deadair holds SIEM credentials and produces reports that map detection blind spots. Treat these
areas as security-sensitive:

- any path that lets a deadair credential write to the monitored SIEM
- any required privilege broader than the documented least-privilege roles
- `--redact` output leaking tenant, source, rule, pattern, or field names
- report, HTML, or state files created with wider-than-expected permissions on POSIX systems
- exporter binding or serving beyond the configured address
- any undisclosed outbound connection or phone-home behavior

## Supported versions

Only the latest release receives security fixes.
