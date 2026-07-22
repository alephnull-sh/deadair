# Backend support policy

deadair maintains compatibility with the current and previous major release lines of each supported
backend. A support claim covers the backend APIs deadair calls, the documented least-privilege role,
rejected-write proof, and the stable report contract. It does not claim compatibility with every
plugin, hosted-provider customization, or prerelease build.

## Current support window

| Backend | Maintained major lines | Exact versions tested in live CI | Compose default |
|---|---|---|---|
| Elastic Security | 9.x current; 8.x previous | 8.19.19 and 9.4.4 | 9.4.4 |
| OpenSearch Security Analytics | 3.x current; 2.x previous | 2.19.6 and 3.7.0 | 3.7.0 |

The exact-version matrix in
[the trusted integration workflow](../.github/workflows/integration.yml) is the source of truth.
Those versions run the least-privilege scan and rejected-write suites on pushes to `main`, merge
queues, the weekly schedule, and manual dispatches. One current-version Elastic/OpenSearch pair also
runs the cross-backend fleet proof.

## Supported and best-effort versions

The exact versions in the live matrix are supported and continuously tested. Other patch or minor
releases within the maintained major lines are best effort: compatibility reports are welcome and
fixes are considered, but those combinations do not become supported until they have repeatable
live integration coverage.

Older major lines, prereleases, vendor-modified distributions, and a newly released major that is
not yet in the matrix are unsupported and best effort. We may help diagnose a redacted reproduction,
but do not promise a fix or release schedule for those versions. Preview backends have their own
published evidence and exit criteria and are not covered by this supported-version promise.

`deadair check` labels an exact matrix version `tested`, another release in a maintained major
`best-effort`, and a version outside those major lines `unsupported`. An unsupported observed version
makes the readiness check fail instead of printing a misleading ready result.

## Moving the window

When a backend publishes a new major release, deadair first adds an exact version to the live matrix
and verifies API compatibility, least-privilege access, and rejected writes. The oldest major can be
removed only after the replacement is passing and the removal has been announced in the roadmap or
release notes for at least 90 days. Removal must update the workflow, compose files, integration and
credential docs, and this page in the same change.

A failing supported-version job blocks a support claim. If an upstream regression cannot be fixed
promptly, the affected exact version is marked degraded or removed from the supported table rather
than silently left green through skipped assertions.
