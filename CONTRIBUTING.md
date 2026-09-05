# Contributing

Please open an issue to report a bug, suggest a change, or share a small reproduction. Include the
deadair version, backend version, what you expected, and what happened. Remove credentials and
customer data before posting.

Maintainers write and merge code changes. We don't accept external pull requests; use an issue to
discuss the problem or proposed approach instead.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Local validation

Use the Go version declared in `go.mod`, then run:

```sh
make validate
```

This runs the same fork-safe checks as pull-request CI: formatting, vet, unit tests, the race
detector, a static build, and a `go mod tidy` comparison. It needs no SIEM credentials and does not
start Docker. The tidy check uses a temporary module file, so it does not rewrite tracked files.
CI also runs `make vuln`; run it locally after dependency or toolchain changes.

Keep tests close to the behavior they cover. Table-driven tests work well for parsers and
normalization. Run the relevant package while working, then run `make validate` before opening the
pull request. CI also builds every macOS, Linux, and Windows release target and runs tests on
Windows.

## Optional live integration tests

Docker integration tests use throwaway Elastic and OpenSearch stacks:

```sh
make elastic-integration
make opensearch-integration
make fleet-integration
```

`make integration` runs all three. See [integration/README.md](integration/README.md) for tested
versions, overrides, setup and cleanup commands, and fixture behavior. Name new tests
`TestElastic*`, `TestOpenSearch*`, or `TestFleet*` so trusted integration CI picks them up.
Pull-request CI never starts these services or receives repository secrets.

Sentinel tests use the `TestSentinel*` prefix and run separately against a disposable Azure lab.
They are not part of `make integration`; the integration guide documents their setup, permissions,
and cleanup.

## The read-only invariant

deadair's production backend interface is read-only. A production credential may list or inspect
rules, sources, mappings, and aggregate statistics. It must not create, update, or delete anything
in the monitored SIEM. Do not add a write method or broaden a documented role to make an
implementation easier.

Integration setup may use an administrator credential only to create and remove synthetic fixtures
inside a throwaway stack. Each backend proof must scan with the documented least-privilege
credential and show that representative writes with that credential are rejected.

## Fixtures, reports, and redaction

Use synthetic fixture names and generated events. Never commit real credentials, customer exports,
tenant names, rule names, index patterns, report files, or state files. Test redaction whenever a
new report field can contain operator-controlled or tenant-identifying text. Public issues and pull
requests should include only `--redact` output and the smallest synthetic reproduction needed.

Report format changes need compatibility tests and documentation. Preserve explicit outcomes for
unsupported or unavailable backend inputs; do not silently turn missing evidence into a healthy
finding.

## Backend changes

Use the [backend RFC template](.github/ISSUE_TEMPLATE/backend_rfc.md) for a new backend, a new
backend major, or a material API or permission change. Include exact versions, API methods,
least-privilege credentials, capability gaps, rejected-write proof, fixtures, and report
compatibility.

Keep the workflow matrix, compose defaults, integration guide, and credential guides aligned when
changing tested versions.
