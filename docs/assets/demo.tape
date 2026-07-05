# vhs tape for the README demo gif: a real `deadair scan` against a live
# Elastic cluster loaded with the full prebuilt detection-rule package.
# Regenerate: boot the integration stack, seed (see integration/), then
# DEADAIR_DEMO_DIR=<staged dir> DEADAIR_DEMO_KEY_FILE=<key> vhs docs/assets/demo.tape
Output docs/assets/demo.gif

Set FontSize 14
Set Width 1060
Set Height 700
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type `export DEADAIR_ES_URL=http://localhost:9200 DEADAIR_KIBANA_URL=http://localhost:5601 DEADAIR_API_KEY=$(cat "$DEADAIR_DEMO_KEY_FILE") PATH="$PWD/bin:$PATH" && cd "$DEADAIR_DEMO_DIR" && clear`
Enter
Sleep 1.5s
Show

Type "deadair scan --state-file deadair-state.json"
Sleep 600ms
Enter
Sleep 3s
Sleep 6s
