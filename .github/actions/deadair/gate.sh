#!/usr/bin/env bash
set -euo pipefail

created=${DEADAIR_ACTION_REPORT_CREATED:-false}
status=${DEADAIR_ACTION_EXIT_CODE:-2}
fail_on_findings=${DEADAIR_ACTION_FAIL_ON_FINDINGS:-true}

if [[ $created != true ]]; then
	printf 'deadair action: scan completed without a JSON report\n' >&2
	exit 2
fi

case "$status" in
0)
	exit 0
	;;
1)
	if [[ $fail_on_findings == false ]]; then
		exit 0
	fi
	exit 1
	;;
2)
	exit 2
	;;
*)
	printf 'deadair action: invalid scan exit code: %s\n' "$status" >&2
	exit 2
	;;
esac
