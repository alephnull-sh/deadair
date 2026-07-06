# vhs tape: MSSP lab operator view from a fresh `make mssp-lab` run.
# Regenerate:
#   make mssp-lab
#   DEADAIR_MSSP_LAB_OUT="$PWD/integration/mssp-lab-out" vhs docs/assets/mssp-lab.tape
Output docs/assets/mssp-lab.gif

Set FontSize 14
Set Width 1060
Set Height 620
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Hide
Type `cd "$DEADAIR_MSSP_LAB_OUT" && clear`
Enter
Sleep 1s
Show

Type "jq '.summary' fleet-redacted.json"
Sleep 500ms
Enter
Sleep 2.5s

Type "echo failed tenants && jq -r '.errors[].instance' fleet-redacted.json"
Sleep 500ms
Enter
Sleep 2.5s

Type "grep -E '^(deadair_up |deadair_instance_up|deadair_detections_dead)' metrics.txt"
Sleep 500ms
Enter
Sleep 3s
