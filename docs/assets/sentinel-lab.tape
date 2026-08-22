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
Set Height 780
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 12ms

Hide
Type `export PATH="$PWD/bin:$PATH" && unset NO_COLOR && clear`
Enter
Sleep 500ms
Show
Type `deadair scan`
Enter
Hide
Sleep 18s
Show
Sleep 10s
