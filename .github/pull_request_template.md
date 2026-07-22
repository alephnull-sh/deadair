## What changed

Describe the operator problem and the smallest useful change.

## How it was checked

- [ ] `make validate`
- [ ] Tests cover the new or changed behavior
- [ ] Docker integration tests were run, or the reason they were not is noted below

## Safety and compatibility

- [ ] Production backend code remains read-only; no monitored-SIEM write API was added
- [ ] Fixtures and examples contain no credentials, customer data, or unredacted SOC names
- [ ] User-facing behavior, support claims, and report contract changes are documented, or none changed
- [ ] New backend work has an accepted backend RFC, or this change does not touch backend APIs

Notes for reviewers:
