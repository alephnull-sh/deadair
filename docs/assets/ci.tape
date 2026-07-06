# vhs tape for the pipeline-checks gif: candidate-rule gate + report diff.
# Staged files: new-rule.json (reads netflow-*, which doesn't exist),
# last-week.json / today.json (reports before/after a source died).
Output docs/assets/ci.gif

Set FontSize 14
Set Width 1060
Set Height 400
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type `export DEADAIR_ES_URL=http://localhost:9200 DEADAIR_KIBANA_URL=http://localhost:5601 DEADAIR_API_KEY=$(cat "$DEADAIR_DEMO_KEY_FILE") PATH="$PWD/bin:$PATH" && cd "$DEADAIR_DEMO_DIR" && clear`
Enter
Sleep 1.5s
Show

Type "deadair scan --rule new-rule.json   # gate a PR: will this rule see data?"
Sleep 600ms
Enter
Sleep 2.5s
Type "echo exit=$?"
Sleep 400ms
Enter
Sleep 2s
Type "deadair diff last-week.json today.json   # what changed since last week?"
Sleep 600ms
Enter
Sleep 2.5s
Sleep 5s
