---
name: deadair-release
description: Prepare and publish a deadair release through its PR, CI, tag, artifact, documentation, and cleanup path without breaking report baselines or public links.
---

# Release deadair

Use the release tag as `VERSION` and inspect the worktree, branch, tags, release notes, workflow,
and current public links before changing release state. The sources of truth are
[Makefile](../../../Makefile), [CI](../../../.github/workflows/ci.yml),
[integration CI](../../../.github/workflows/integration.yml),
[the release workflow](../../../.github/workflows/release.yml), and
[the tag-specific release notes](../../../.github/release-notes).

## Freeze the candidate before recording it

- Finish product and presentation changes first. Regenerate examples and captures only after the
  output is stable, using the intended tag so producer metadata matches the release.
- Check every generated terminal, JSON, HTML, still, and animation. A successfully generated but
  stale asset is a release failure.
- Keep release notes curated and tag-specific. State live-versus-fixture limits beside the feature
  they constrain. Do not fill notes with commit-log summaries or internal process narration.
- Treat report comparison identity as part of the release contract. Schema, backend, instance,
  target, redaction key, filters, candidate set, assessment configuration, and normalized Sentinel
  remote mappings must match for `diff`. If a release changes any identity input or lacks fields an
  older report needs, say that a fresh baseline is required; never imply unlike reports are
  comparable.

## Run the whole release boundary

Before the PR is ready, run:

1. focused tests and `git diff --check`;
2. `make validate` and `make vuln` with a Go toolchain at least as new as the patch version required
   by `go.mod`;
3. the current Elastic, OpenSearch, mixed-fleet, MSSP, and Sentinel proofs affected by the change;
4. `bash .github/actions/deadair/test.sh` and `bash .github/release-notes/test.sh`;
5. all six release cross-builds, checksums, and any SBOM or provenance preparation the workflow
   requires.

Compare the local command set with the current workflows rather than copying an old release's
matrix. Remove generated QA directories and keep credentials, state, lab output, and unredacted
reports out of the commit.

## Publish through the repository workflow

Loading this skill or asking for release preparation does not authorize a commit, push, PR, tag,
release, history rewrite, deployment deletion, or other GitHub mutation. Stop before each external
action unless the user's current request explicitly authorizes that action or a clearly bounded
sequence containing it.

When authorized, commit and push the candidate branch, open the PR, and wait for required CI. After
merge, verify the exact merge commit and required `main` workflows. Tag that tested commit only with
explicit release authorization. Pushing the tag starts the release workflow; do not also create a
release manually or upload a second set of assets.

Wait for both build and publish jobs. Verify the release contains the six platform binaries, SBOM,
checksums, and curated notes expected by the workflow. Verify the GitHub build-provenance and SBOM
attestations separately. Download the published bundle, check every checksum, install or run at
least one released binary, confirm its version, and open the release and documentation links as an
anonymous reader.

## Preserve public references

Do not rewrite branch or tag history, move or delete releases, rename GitHub Pages paths, remove
published asset paths, or replace the technical article's route during an ordinary release. The
README's technical write-up and publication links are part of the public surface. A docs refresh
must keep historical captures and frozen article sections intact unless the task explicitly says
otherwise.

History cleanup is a separate operation: require its own authorization, fresh mirror, backups,
reference inventory, and post-push link verification. Never mix it into release preparation.

Update an external research article only after the release URL and source revision exist. Add a
dated release update rather than rewriting the original record, keep the same route, name the exact
live validation boundary, and link the published release and source revision.

## Close the release

Recheck the release, checksum, Pages, article, and publication URLs after propagation. Only then
remove exact disposable lab fixtures through their fail-closed cleanup path and delete temporary
credentials or local capture state. Do not remove live deployments as a way to tidy history. Record
what was verified and what intentionally remains.
