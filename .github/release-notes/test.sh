#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$repo_root/.github/workflows/release.yml"
release_version="v0.7.0"
notes="$repo_root/.github/release-notes/${release_version}.md"

grep -Fq 'notes_path=".github/release-notes/${VERSION}.md"' "$workflow"
grep -Fq 'if [ ! -s "$notes_path" ]; then' "$workflow"
grep -Fq 'cp -- "$notes_path" release-notes.md' "$workflow"

if grep -Eq 'git log|--generate-notes' "$workflow"; then
	printf 'release workflow must use curated tag-specific notes\n' >&2
	exit 1
fi

test -s "$notes"
grep -Fxq "# ${release_version}" "$notes"
