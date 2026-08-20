#!/usr/bin/env bash
set -euo pipefail

runner_tmp=${RUNNER_TEMP:?RUNNER_TEMP is not set}
github_output=${GITHUB_OUTPUT:?GITHUB_OUTPUT is not set}
binary="$runner_tmp/deadair-action/deadair"
report_dir=$(mktemp -d "$runner_tmp/deadair-action-report.XXXXXX")
report_path="$report_dir/deadair-report.json"

args=(scan)
if [[ -n ${DEADAIR_ACTION_SCAN_ARGS:-} ]]; then
	# Deliberately split on whitespace without eval. Values containing spaces
	# should be supplied through environment variables or config files.
	read -r -a extra_args <<<"$DEADAIR_ACTION_SCAN_ARGS"
	for arg in "${extra_args[@]}"; do
		case "$arg" in
		-backend | -backend=* | --backend | --backend=* | \
		-es-url | -es-url=* | --es-url | --es-url=* | \
		-kibana-url | -kibana-url=* | --kibana-url | --kibana-url=* | \
		-opensearch-url | -opensearch-url=* | --opensearch-url | --opensearch-url=* | \
		-api-key-file | -api-key-file=* | --api-key-file | --api-key-file=* | \
		-opensearch-username | -opensearch-username=* | --opensearch-username | --opensearch-username=* | \
		-opensearch-password-file | -opensearch-password-file=* | --opensearch-password-file | --opensearch-password-file=* | \
		-fleet | -fleet=* | --fleet | --fleet=* | \
		-json | -json=* | --json | --json=* | \
		-json-out | -json-out=* | --json-out | --json-out=* | \
		-html-out | -html-out=* | --html-out | --html-out=* | \
		-out | -out=* | --out | --out=* | \
		-h | --help | \
			-redact | -redact=* | --redact | --redact=* | \
			-redact-key-file | -redact-key-file=* | --redact-key-file | --redact-key-file=* | \
			-policy | -policy=* | --policy | --policy=* | \
			-rule | -rule=* | --rule | --rule=*)
			printf 'deadair action: %s is not accepted in scan-args; use a dedicated input or run the CLI directly\n' "$arg" >&2
			exit 2
			;;
		esac
	done
	args+=("${extra_args[@]}")
fi
if [[ -n ${DEADAIR_ACTION_API_KEY_FILE:-} ]]; then
	args+=(--api-key-file "$DEADAIR_ACTION_API_KEY_FILE")
fi
if [[ -n ${DEADAIR_ACTION_OPENSEARCH_PASSWORD_FILE:-} ]]; then
	args+=(--opensearch-password-file "$DEADAIR_ACTION_OPENSEARCH_PASSWORD_FILE")
fi
if [[ -n ${DEADAIR_ACTION_CANDIDATE_RULE:-} ]]; then
	args+=(--rule "$DEADAIR_ACTION_CANDIDATE_RULE")
fi
if [[ -n ${DEADAIR_ACTION_POLICY_FILE:-} ]]; then
	args+=(--policy "$DEADAIR_ACTION_POLICY_FILE")
fi
# Only the explicit value "false" disables redaction. Typos stay on the safe
# side, and a key file always implies redaction.
if [[ ${DEADAIR_ACTION_REDACT_REPORT:-true} != false || -n ${DEADAIR_ACTION_REDACT_KEY_FILE:-} ]]; then
	args+=(--redact)
fi
if [[ -n ${DEADAIR_ACTION_REDACT_KEY_FILE:-} ]]; then
	args+=(--redact-key-file "$DEADAIR_ACTION_REDACT_KEY_FILE")
fi
args+=(--json-out "$report_path")

set +e
"$binary" "${args[@]}"
status=$?
set -e

created=false
if [[ -s $report_path ]]; then
	created=true
fi

{
	printf 'report-path=%s\n' "$report_path"
	printf 'report-created=%s\n' "$created"
	printf 'exit-code=%s\n' "$status"
} >>"$github_output"

# Exit 0 here so the summary and evidence upload always run. The final action
# step applies the requested finding policy and always propagates scan errors.
exit 0
