# vhs tape: the first-run journey. Bare invocation shows help and points at
# setup; setup prints the credential walkthrough; check confirms it worked.
# Needs a live cluster for the check step (integration/demo-env.sh).
Output docs/assets/onboarding.gif
Set FontSize 14
Set Width 1060
Set Height 620
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Hide
Type `export PATH="$PWD/bin:$PATH" DEADAIR_DEMO_KEY="$PWD/integration/demo-key" && unset DEADAIR_ES_URL DEADAIR_KIBANA_URL DEADAIR_API_KEY && clear`
Enter
Sleep 1s
Show
Type "deadair"
Sleep 500ms
Enter
Sleep 2.5s
Type "deadair setup | tail -5"
Sleep 500ms
Enter
Sleep 2s
Hide
Type `export DEADAIR_ES_URL=http://localhost:9200 DEADAIR_KIBANA_URL=http://localhost:5601 DEADAIR_API_KEY=$(cat "$DEADAIR_DEMO_KEY") && clear`
Enter
Sleep 500ms
Show
Type "deadair check"
Sleep 500ms
Enter
Sleep 2.5s
Sleep 5s
