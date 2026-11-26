#!/usr/bin/env bash
set -euo pipefail

summary=${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is not set}
report=${DEADAIR_ACTION_REPORT_PATH:-}
status=${DEADAIR_ACTION_EXIT_CODE:-2}

if [[ -z $report || ! -s $report ]]; then
	result="Scan error"
else
	case "$status" in
		0) result="Passed" ;;
		1) result="Findings" ;;
		*) result="Scan error" ;;
	esac
fi

{
	printf '## deadair scan\n\n'
	printf '**Result:** %s (exit %s)\n\n' "$result" "$status"
} >>"$summary"

if [[ -z $report || ! -s $report ]]; then
	printf 'No JSON report was produced. Check the scan log for the connection or configuration error.\n' >>"$summary"
	exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
	printf 'The JSON report was produced, but jq was unavailable for the summary.\n' >>"$summary"
	exit 0
fi

jq -r '
  .summary as $s |
  ([
    "| Measure | Count |",
    "|---|---:|",
    "| Enabled rules | \($s.enabled_rules // 0) |",
    "| Sources | \($s.sources // 0) |",
    "| Dead detections | \($s.dead_detections // 0) |",
    "| Impaired detections | \($s.impaired_detections // 0) |"
  ] +
  (if .policy then ["| Policy-gated findings | \($s.gated_findings // 0) |"] else [] end) +
  [
    "| Degraded sources | \($s.degraded_sources // 0) |"
  ] +
  (if (($s.unused_telemetry_assessment // "") == "unavailable" or ($s.unused_telemetry_assessment // "") == "not-applicable")
   then []
   else ["| Unused sources | \($s.unused_sources // 0) |"]
   end))[]
' "$report" >>"$summary"

jq -r '
  def mdcell: tostring | gsub("[\\r\\n\\t]+"; " ") | gsub("\\|"; "\\|");
  (.findings // []) as $f |
  if ($f | length) == 0 then empty
  else
    ([
      "",
      "### Findings",
      "",
      "| Class | Subject | Reason | Gate |",
      "|---|---|---|---|"
    ] +
    ($f[:15] | map(
      "| \((.class // "-") | mdcell) | \((.rule_name // .rule_id // .source // "-") | mdcell) | \((if (.dependency // "") != "" then "\(.reason // "-") (\(.dependency))" else (.reason // "-") end) | mdcell) | \(if (.accepted.status // "") == "active" then "accepted" elif .suppressed then "suppressed" elif .gates then "gated" else "info" end) |"
    )) +
    (if ($f | length) > 15 then ["", "_…and \(($f | length) - 15) more finding(s) in the JSON artifact._"] else [] end))[]
  end
' "$report" >>"$summary"

printf '\nThe full evidence is attached as the workflow artifact.\n' >>"$summary"

