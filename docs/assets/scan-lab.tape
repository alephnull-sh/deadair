# Real Elastic lab capture. The preparation script creates five live rules and
# sources that deliberately exercise healthy, missing, stale, schema, lag, and
# unused-telemetry paths.
# Regenerate from the repository root:
#   make record-scan-lab

Output docs/assets/scan-lab.gif
Output docs/assets/scan-lab.mp4

Set FontSize 16
Set Width 980
Set Height 760
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 12ms
Set Shell "bash"

Hide
Type `export PATH="$PWD/bin:$PATH" DEADAIR_ES_URL="${DEADAIR_IT_ES_URL:-http://localhost:9200}" DEADAIR_KIBANA_URL="${DEADAIR_IT_KIBANA_URL:-http://localhost:5601}" DEADAIR_API_KEY=$(cat "$DEADAIR_SCAN_LAB_OUT/api-key") PS1='$ ' && unset NO_COLOR && cd "$DEADAIR_SCAN_LAB_OUT" && clear`
Enter
Sleep 500ms
Type "deadair scan --schema --state-file capture-state.json --json-out report.json"
Enter
Wait+Screen@30s /Inspect: deadair inspect/
Show
Screenshot docs/assets/scan-lab.png
Sleep 8s

Hide
Ctrl+L
Type "deadair inspect --source endpoint-process-events-legacy report.json"
Enter
Wait+Screen /transform/
Type "deadair inspect --source cloudflare-firewall-prod report.json"
Enter
Wait+Screen /collector queues/
Show
Sleep 8s
