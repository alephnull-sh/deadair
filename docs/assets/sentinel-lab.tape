# Record a read-only scan of an existing disposable Sentinel lab:
#   az login --tenant <tenant-id>
#   DEADAIR_AZURE_SUBSCRIPTION_ID=... \
#   DEADAIR_AZURE_RESOURCE_GROUP=... \
#   DEADAIR_SENTINEL_WORKSPACE=... \
#   DEADAIR_SENTINEL_CAPTURE_CONFIRM=record-disposable-sentinel:<workspace> \
#   VERSION=v0.7.0 make record-sentinel-lab

Output docs/assets/sentinel-lab.gif

Set FontSize 14
Set Width 1060
Set Height 900
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 25ms

Hide
Type `export PATH="$PWD/bin:$PATH" && unset NO_COLOR && clear`
Enter
Sleep 500ms
Show

Type "deadair check"
Enter
Sleep 10s
Ctrl+L
Sleep 500ms
Type "deadair scan"
Enter
Sleep 16s
