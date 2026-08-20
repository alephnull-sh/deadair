#!/usr/bin/env bash
set -euo pipefail

action_dir=${GITHUB_ACTION_PATH:?GITHUB_ACTION_PATH is not set}
runner_tmp=${RUNNER_TEMP:?RUNNER_TEMP is not set}
version=${DEADAIR_ACTION_VERSION:-action}
binary_dir="$runner_tmp/deadair-action"

mkdir -p "$binary_dir"
cd "$action_dir"
CGO_ENABLED=0 go build \
	-trimpath \
	-ldflags "-s -w -X github.com/alephnull-sh/deadair/internal/cli.Version=$version" \
	-o "$binary_dir/deadair" \
	./cmd/deadair
