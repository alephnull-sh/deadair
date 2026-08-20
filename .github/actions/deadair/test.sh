#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
action_file=$(cd "$script_dir/../../.." && pwd)/action.yml
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

bash -n "$script_dir/build.sh" "$script_dir/scan.sh" "$script_dir/summary.sh" "$script_dir/gate.sh"

step_count=$(grep -c '^    - name:' "$action_file")
non_scan_steps=$((step_count - 1))
credential_env=(
	DEADAIR_BACKEND DEADAIR_ES_URL DEADAIR_KIBANA_URL DEADAIR_API_KEY
	DEADAIR_OPENSEARCH_URL DEADAIR_OPENSEARCH_USERNAME
	DEADAIR_OPENSEARCH_PASSWORD DEADAIR_OPENSEARCH_API_KEY
)
credential_input=(
	backend elasticsearch-url kibana-url api-key
	opensearch-url opensearch-username opensearch-password opensearch-api-key
)
for i in "${!credential_env[@]}"; do
	name=${credential_env[$i]}
	blank_count=$(grep -Fc "        $name: \"\"" "$action_file" || true)
	if [[ $blank_count -ne $non_scan_steps ]]; then
		printf '%s is not blanked in every non-scan Action step\n' "$name" >&2
		exit 1
	fi
	expected_mapping=$(printf '        %s: ${{ inputs.%s }}' "$name" "${credential_input[$i]}")
	grep -Fq "$expected_mapping" "$action_file"
done
redact_blank_count=$(grep -Fc '        DEADAIR_REDACT_KEY_FILE: ""' "$action_file" || true)
if [[ $redact_blank_count -ne $step_count ]]; then
	printf 'DEADAIR_REDACT_KEY_FILE is not blanked in every Action step\n' >&2
	exit 1
fi

runner_tmp="$tmp_dir/runner"
binary_dir="$runner_tmp/deadair-action"
mkdir -p "$binary_dir"

stub="$binary_dir/deadair"
printf '%s\n' \
	'#!/usr/bin/env bash' \
	'set -euo pipefail' \
	': "${DEADAIR_ACTION_TEST_ARGS:?}"' \
	': >"$DEADAIR_ACTION_TEST_ARGS"' \
	'report=""' \
	'while (($#)); do' \
	'  printf "%s\\n" "$1" >>"$DEADAIR_ACTION_TEST_ARGS"' \
	'  if [[ $1 == --json-out ]]; then' \
	'    shift' \
	'    report=$1' \
	'    printf "%s\\n" "$1" >>"$DEADAIR_ACTION_TEST_ARGS"' \
	'  fi' \
	'  shift' \
	'done' \
	'if [[ ${DEADAIR_ACTION_TEST_WRITE_REPORT:-true} == true && -n $report ]]; then' \
	'  mkdir -p "$(dirname "$report")"' \
	'  printf "%s\\n" '\''{"summary":{"enabled_rules":3,"sources":2,"dead_detections":1,"impaired_detections":0,"gated_findings":1,"degraded_sources":1,"unused_sources":0},"policy":{"version":1}}'\'' >"$report"' \
	'fi' \
	'exit "${DEADAIR_ACTION_TEST_EXIT:-0}"' \
	>"$stub"
chmod +x "$stub"

reserved_output="$tmp_dir/reserved-output"
: >"$reserved_output"
for reserved in \
	'--redact=false' '-redact=false' '--json' '-out=other.json' \
	'--api-key-file=other.key' '--backend=opensearch' '--fleet=fleet.json' \
	'-h' '--help'; do
	set +e
	RUNNER_TEMP="$runner_tmp" \
		GITHUB_OUTPUT="$reserved_output" \
		DEADAIR_ACTION_SCAN_ARGS="$reserved" \
		bash "$script_dir/scan.sh" >"$tmp_dir/reserved-stdout" 2>"$tmp_dir/reserved-stderr"
	reserved_status=$?
	set -e
	if [[ $reserved_status -ne 2 ]]; then
		printf 'reserved option %s exit = %s, want 2\n' "$reserved" "$reserved_status" >&2
		exit 1
	fi
	grep -Fq 'is not accepted in scan-args' "$tmp_dir/reserved-stderr"
done

scan_output="$tmp_dir/scan-output"
args_output="$tmp_dir/scan-args"
: >"$scan_output"
RUNNER_TEMP="$runner_tmp" \
	GITHUB_OUTPUT="$scan_output" \
	DEADAIR_ACTION_CANDIDATE_RULE='candidate.json' \
	DEADAIR_ACTION_POLICY_FILE='policy.json' \
	DEADAIR_ACTION_API_KEY_FILE='api-key.file' \
	DEADAIR_ACTION_OPENSEARCH_PASSWORD_FILE='opensearch-password.file' \
	DEADAIR_ACTION_REDACT_REPORT='true' \
	DEADAIR_ACTION_REDACT_KEY_FILE='redaction.key' \
	DEADAIR_ACTION_SCAN_ARGS='--max-stale 45m' \
	DEADAIR_ACTION_TEST_ARGS="$args_output" \
	DEADAIR_ACTION_TEST_EXIT=1 \
	bash "$script_dir/scan.sh"

grep -Fxq 'exit-code=1' "$scan_output"
grep -Fxq 'report-created=true' "$scan_output"
grep -Fxq -- '--redact' "$args_output"
grep -Fxq -- '--redact-key-file' "$args_output"
grep -Fxq -- '--api-key-file' "$args_output"
grep -Fxq -- '--opensearch-password-file' "$args_output"
grep -Fxq -- '--policy' "$args_output"
grep -Fxq -- '--rule' "$args_output"
if [[ $(tail -n 2 "$args_output" | head -n 1) != --json-out ]]; then
	printf 'Action-owned --json-out was not appended last\n' >&2
	exit 1
fi

report_path=$(sed -n 's/^report-path=//p' "$scan_output")

second_scan_output="$tmp_dir/second-scan-output"
: >"$second_scan_output"
RUNNER_TEMP="$runner_tmp" \
	GITHUB_OUTPUT="$second_scan_output" \
	DEADAIR_ACTION_REDACT_REPORT='true' \
	DEADAIR_ACTION_TEST_ARGS="$tmp_dir/second-scan-args" \
	bash "$script_dir/scan.sh"
second_report_path=$(sed -n 's/^report-path=//p' "$second_scan_output")
if [[ $report_path == "$second_report_path" ]]; then
	printf 'repeated Action scans reused report path %s\n' "$report_path" >&2
	exit 1
fi
test -s "$report_path"
test -s "$second_report_path"

summary_path="$tmp_dir/summary"
: >"$summary_path"
GITHUB_STEP_SUMMARY="$summary_path" \
	DEADAIR_ACTION_REPORT_PATH="$report_path" \
	DEADAIR_ACTION_EXIT_CODE=1 \
	bash "$script_dir/summary.sh"
grep -Fq '**Result:** Findings (exit 1)' "$summary_path"
grep -Fq '| Policy-gated findings | 1 |' "$summary_path"

passed_report="$tmp_dir/passed-report.json"
printf '%s\n' '{"summary":{"enabled_rules":3,"sources":2,"dead_detections":2,"impaired_detections":1,"gated_findings":0,"degraded_sources":0,"unused_sources":0},"policy":{"version":1}}' >"$passed_report"
passed_summary="$tmp_dir/passed-summary"
: >"$passed_summary"
GITHUB_STEP_SUMMARY="$passed_summary" \
	DEADAIR_ACTION_REPORT_PATH="$passed_report" \
	DEADAIR_ACTION_EXIT_CODE=0 \
	bash "$script_dir/summary.sh"
grep -Fq '**Result:** Passed (exit 0)' "$passed_summary"
grep -Fq '| Dead detections | 2 |' "$passed_summary"
grep -Fq '| Impaired detections | 1 |' "$passed_summary"
grep -Fq '| Policy-gated findings | 0 |' "$passed_summary"
if grep -Fq 'Healthy' "$passed_summary"; then
	printf 'exit 0 summary must not call a policy result healthy\n' >&2
	exit 1
fi

error_output="$tmp_dir/error-output"
: >"$error_output"
RUNNER_TEMP="$runner_tmp" \
	GITHUB_OUTPUT="$error_output" \
	DEADAIR_ACTION_REDACT_REPORT='true' \
	DEADAIR_ACTION_TEST_ARGS="$tmp_dir/error-args" \
	DEADAIR_ACTION_TEST_EXIT=2 \
	DEADAIR_ACTION_TEST_WRITE_REPORT=false \
	bash "$script_dir/scan.sh"
grep -Fxq 'exit-code=2' "$error_output"
grep -Fxq 'report-created=false' "$error_output"

missing_summary="$tmp_dir/missing-summary"
: >"$missing_summary"
GITHUB_STEP_SUMMARY="$missing_summary" \
	DEADAIR_ACTION_REPORT_PATH=$(sed -n 's/^report-path=//p' "$error_output") \
	DEADAIR_ACTION_EXIT_CODE=0 \
	bash "$script_dir/summary.sh"
grep -Fq '**Result:** Scan error (exit 0)' "$missing_summary"
grep -Fq 'No JSON report was produced.' "$missing_summary"
if grep -Fq '**Result:** Passed' "$missing_summary"; then
	printf 'missing report summary must not report a pass\n' >&2
	exit 1
fi

set +e
DEADAIR_ACTION_REPORT_CREATED=false \
	DEADAIR_ACTION_EXIT_CODE=0 \
	DEADAIR_ACTION_FAIL_ON_FINDINGS=false \
	bash "$script_dir/gate.sh" >"$tmp_dir/gate-missing-stdout" 2>"$tmp_dir/gate-missing-stderr"
gate_status=$?
set -e
if [[ $gate_status -ne 2 ]]; then
	printf 'missing report gate exit = %s, want 2\n' "$gate_status" >&2
	exit 1
fi
grep -Fq 'scan completed without a JSON report' "$tmp_dir/gate-missing-stderr"

DEADAIR_ACTION_REPORT_CREATED=true \
	DEADAIR_ACTION_EXIT_CODE=0 \
	DEADAIR_ACTION_FAIL_ON_FINDINGS=true \
	bash "$script_dir/gate.sh"

DEADAIR_ACTION_REPORT_CREATED=true \
	DEADAIR_ACTION_EXIT_CODE=1 \
	DEADAIR_ACTION_FAIL_ON_FINDINGS=false \
	bash "$script_dir/gate.sh"
