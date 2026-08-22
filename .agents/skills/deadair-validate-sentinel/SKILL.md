---
name: deadair-validate-sentinel
description: Provision, test, capture, or clean a disposable Microsoft Sentinel conformance lab while enforcing exact ownership, least privilege, and read-only scanner proof.
---

# Validate Sentinel safely

Read the Sentinel section of the [integration guide](../../../integration/README.md), the
[credential guide](../../../docs/credentials/sentinel.md), and both provisioners before touching
Azure:

- [base lab](../../../integration/prepare-sentinel-base-lab.sh)
- [expansion lab](../../../integration/prepare-sentinel-expansion-lab.sh)

The scripts, their current confirmation strings, and
[the conformance tests](../../../integration/sentinel_test.go) are the source of truth. Do not paste
tenant, subscription, workspace, client, object, or role IDs into the repository or this skill.

## Separate provisioning from scanning

- Use an administrator identity only to create fixtures inside a dedicated disposable resource
  group and workspaces. Confirm the subscription context, exact targets, Sentinel onboarding,
  resource-provider registration, a small budget alert, and required ingestion permission first.
- Run the scanner with the documented workspace-scoped custom role and a certificate-backed
  `EnvironmentCredential`: set the tenant, client, and certificate environment; set
  `AZURE_TOKEN_CREDENTIALS=EnvironmentCredential`; leave the client secret unset; and require the
  scanner client ID assertion to match. Azure CLI fallback is not scanner conformance.
- Normal `check`, `scan`, and the Go conformance test must remain read-only. The lab scripts are the
  only fixture writers.

## Provision only what can be owned exactly

Run the base script's offline `plan` before its `apply`; base `apply` performs its own live
preflight. Run expansion `verify` before expansion `apply`, then again after provisioning. Resolve
the workspace customer UUID independently from its resource name. Stop on any collision in
resource IDs, rules, functions, tables, watchlists, diagnostic settings, remote onboarding, or
summary resources.

Every owned resource needs an exact definition or marker that can be re-read before mutation.
Never adopt a same-named resource, repair a base fixture from the expansion script, run fixture
writers concurrently, or broaden a cleanup selector. Wait for Azure resources to reach stable
states and re-check their definitions before ingesting evidence.

Use realistic synthetic tables and controlled rows. Keep operator-facing names organic; retain
deadair ownership in IDs, descriptions, or tags. Time windows must isolate the intended case, such
as a stale vendor slice that remains inside the rule's lookback so it is not also an ordinary lag
failure.

## Require positive and negative proof

A release-grade pass includes, in this order:

1. Base and expansion read-only preflight, including exact plans, schemas, rule/function
   definitions, current rows, Basic Logs evidence, and the expected source-bin aggregate.
2. After expansion creates a remote workspace, resolve its exact resource scope, assign the
   documented scanner role there with the provisioner identity, and wait until RBAC propagation is
   proven under the certificate-only scanner. Do not broaden the assignment to the subscription or
   resource group.
3. Expansion `verify` after provisioning and after any evidence refresh.
4. `TestSentinelReadOnlyLab` under the certificate-only scanner identity.
5. `TestSentinelWriteDenials` under that same scanner identity.

The read-only proof must exercise healthy sources as well as deliberately missing, stale, empty,
late, incompatible, partial, and unavailable evidence. Treat semantic `PartialError`, denied
queries, missing onboarding, ambiguous KQL, and absent cross-subscription execution evidence as
unassessed; do not turn them into missing tables or successful resolution.

For write denials, first prove the fixed rule and table deletion targets do not exist. Require exact
HTTP `403` responses for both DELETE requests and the shared-keys POST. Any `2xx`, unexpected
status, or successful shared-key body is a failed safety proof.

Record the exact live boundary in [validation status](../../../docs/validation.md). Fixture-only,
single-subscription, same-region, empty-inventory, or advisory evidence must not be described as a
broader live proof. A demo capture may use the repository's explicit capture target after
conformance, but it does not replace the certificate-only scanner test.

## Clean up fail-closed

Do not clean while proof or fresh captures still depend on the lab. When authorized, clean
expansion fixtures before base fixtures, using each script's explicit confirmation value. Re-read
every full marker immediately before deletion and stop if a marker changed, disappeared
unexpectedly, or reports an in-progress lifecycle. Leave the resource group, workspaces, Sentinel
onboarding, budget, and role assignments alone unless they are separately and exactly authorized.

Azure retains deleted table names and data for a recovery period, so cleanup is terminal for that
workspace. Use a fresh workspace for an immediate clean rerun. Report what was removed and what
was intentionally retained.
