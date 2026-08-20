# Real Elastic lab capture. The preparation script creates five live rules and
# sources that deliberately exercise healthy, missing, stale, schema, lag, and
# unused-telemetry paths.
# Regenerate from the repository root:
#   make record-scan-lab

Output docs/assets/scan-lab.gif

Set FontSize 14
Set Width 1060
Set Height 480
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Hide
Type `export PATH="$PWD/bin:$PATH" DEADAIR_ES_URL=http://localhost:9200 DEADAIR_KIBANA_URL=http://localhost:5601 DEADAIR_API_KEY=$(cat "$DEADAIR_SCAN_LAB_OUT/api-key") && unset NO_COLOR && cd "$DEADAIR_SCAN_LAB_OUT" && clear`
Enter
Sleep 500ms
Show

Type "deadair check"
Enter
Sleep 3s

Ctrl+L
Sleep 500ms

Type "deadair scan --schema --state-file capture-state.json"
Enter
Sleep 5s
Screenshot docs/assets/scan-lab.png
Sleep 2s
