# Real readiness check against the disposable Elastic screenshot lab.
# Regenerate from the repository root:
#   make record-scan-lab

Set FontSize 14
Set Width 1060
Set Height 400
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Hide
Type `export PATH="$PWD/bin:$PATH" DEADAIR_ES_URL=http://localhost:9200 DEADAIR_KIBANA_URL=http://localhost:5601 DEADAIR_API_KEY=$(cat "$DEADAIR_SCAN_LAB_OUT/api-key") && unset NO_COLOR && clear`
Enter
Sleep 500ms
Show

Type "deadair check"
Enter
Sleep 3s
Screenshot docs/assets/check-lab.png
Sleep 1s
