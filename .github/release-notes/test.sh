#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$repo_root/.github/workflows/release.yml"
notes="$repo_root/.github/release-notes/v0.6.0.md"

grep -Fq 'notes_path=".github/release-notes/${VERSION}.md"' "$workflow"
grep -Fq 'if [ ! -s "$notes_path" ]; then' "$workflow"
grep -Fq 'cp -- "$notes_path" release-notes.md' "$workflow"

if grep -Eq 'git log|--generate-notes' "$workflow"; then
	printf 'release workflow must use curated tag-specific notes\n' >&2
	exit 1
fi

test -s "$notes"
