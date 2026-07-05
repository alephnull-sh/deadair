# Contributing

**Maintainership note:** this project is single-maintainer for now, and external pull requests
are not being accepted yet — CI runs live-cluster integration suites that cannot safely run on
fork PRs. Issues, bug reports, and feature discussion are welcome; use the tool freely under
Apache-2.0. The rest of this document describes the standards that will apply when PRs open up.

Ground rules, in order of importance:

## Invariants

Eight invariants govern every change: read-only backends (no write methods, ever), no
telemetry or new outbound destinations, redaction completeness for every name-carrying field,
verdict conservatism (uncertainty never pages), SIEM-safe bounded queries, stable exit codes and
additive-only JSON, zero runtime dependencies, and the permanent non-goals in docs/architecture.md. PRs
that break one will be declined regardless of the feature — open an issue first if you think an
invariant is wrong.

## Dev loop

```sh
make check          # vet + race tests + gofmt gate — must pass before any PR
make integration    # live proof against docker Elastic + OpenSearch (needs docker)
```

- Go stdlib only; a new dependency needs a maintainer's explicit sign-off in the issue first.
- Table-driven unit tests, plus an end-to-end path through `cli.Run` against `httptest` fixtures
  for anything user-visible (see `internal/cli/cli_test.go` for the pattern).
- Integration test functions must be named `TestElastic*` or `TestOpenSearch*` — CI partitions
  on those prefixes and anything else silently never runs.
- Wrap errors with context; per-source failures during a scan must degrade to `unknown`, never
  kill the report.

## Backends

New-backend proposals are welcome — open an issue first. Read [docs/architecture.md](docs/architecture.md)
for what a backend must provide (Splunk is a permanent non-goal). A backend PR needs
the read-only integration proof (rejected writes asserted against a live docker instance) and a
least-privilege credential guide under docs/credentials/.

## Commits

Small, reviewable commits; explain the *why* in the message body. If your change alters report
JSON, additive only — released field names are frozen.
