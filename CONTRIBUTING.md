# Contributing

External pull requests are welcome. Start with an issue for backend work or a change that affects
the report contract, permissions, support claims, or command behavior. Small bug fixes and tests can
go straight to a pull request.

## Local validation

Use the Go version declared in `go.mod`, then run:

```sh
make validate
```

This is the same fork-safe baseline used by pull-request CI: formatting, vet, unit tests, the race
detector, a static build, and a `go mod tidy` comparison. It needs no SIEM credentials and does not
start Docker. The tidy check uses a temporary module file and does not rewrite tracked module files.

Keep tests close to the behavior they cover. Table-driven unit tests are a good fit for parsers and
normalization. Run a focused package while iterating, then run `make validate` before sending the
change. CI also builds all macOS, Linux, and Windows release targets and runs tests on Windows.

## Optional live integration tests

Docker integration tests use throwaway Elastic and OpenSearch stacks:

```sh
make elastic-integration
make opensearch-integration
make fleet-integration
```

`make integration` runs all three. See [integration/README.md](integration/README.md) for exact
versions, overrides, startup/teardown commands, and fixture behavior. New tests must follow the
`TestElastic*`, `TestOpenSearch*`, or `TestFleet*` naming convention so trusted integration CI runs
them. Pull-request CI never starts these services or receives repository secrets.

## The read-only invariant

deadair's production backend interface is read-only. A production credential may list or inspect
rules, sources, mappings, and aggregate statistics; it must not create, update, or delete monitored
SIEM objects. Do not add a write method or broaden a documented role to make an implementation
easier.

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

A new backend, new backend major, or material API/permission change starts with the
[backend RFC template](.github/ISSUE_TEMPLATE/backend_rfc.md). The RFC must cover exact versions,
API methods, least-privilege credentials, normalized capability gaps, rejected-write proof,
fixtures, report compatibility, and preview exit criteria. Splunk remains out of scope.

Backend support and removal rules are in [docs/support-policy.md](docs/support-policy.md). Keep the
workflow matrix, compose defaults, integration guide, credential guides, and support policy aligned
when changing tested versions.
