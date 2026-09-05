# Real readiness check against the disposable Elastic capture lab.
# Regenerate from the repository root:
#   make record-scan-lab

Set FontSize 14
Set Width 1060
Set Height 300
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms
Set Shell "bash"

Hide
Type `export PATH="$PWD/bin:$PATH" DEADAIR_ES_URL="${DEADAIR_IT_ES_URL:-http://localhost:9200}" DEADAIR_KIBANA_URL="${DEADAIR_IT_KIBANA_URL:-http://localhost:5601}" DEADAIR_API_KEY=$(cat "$DEADAIR_SCAN_LAB_OUT/api-key") PS1='$ ' && unset NO_COLOR && clear`
Enter
Sleep 500ms
Show

Type "deadair check"
Enter
Wait+Screen@30s /READY/
Sleep 500ms
Screenshot docs/assets/check-lab.png
Sleep 1s
