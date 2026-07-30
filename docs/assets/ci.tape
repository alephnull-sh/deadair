# vhs tape: candidate-rule gate followed by a report regression check.
# Regenerate from the repository root:
#   make record-ci
Output docs/assets/ci.gif

Set FontSize 14
Set Width 1060
Set Height 440
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms

Hide
Type `export PATH="$PWD/bin:$PATH" DEADAIR_ES_URL=http://localhost:9200 DEADAIR_KIBANA_URL=http://localhost:5601 DEADAIR_API_KEY=$(cat "$DEADAIR_CI_OUT/api-key") && unset NO_COLOR && cd "$DEADAIR_CI_OUT" && clear`
Enter
Sleep 500ms
Show

Type "deadair scan --rule candidate-rule.json"
Sleep 300ms
Enter
Sleep 2s

Type "echo exit=$?"
Sleep 250ms
Enter
Sleep 750ms

Type "deadair diff baseline.json candidate.json"
Sleep 300ms
Enter
Sleep 3s
