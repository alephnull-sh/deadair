# Record producer failure and recovery reports from a disposable Sentinel lab.
# Keep producer-failed.json and producer-recovered.json in a private directory.
#   DEADAIR_AZURE_SUBSCRIPTION_ID=... \
#   DEADAIR_AZURE_RESOURCE_GROUP=... \
#   DEADAIR_SENTINEL_WORKSPACE=... \
#   DEADAIR_SENTINEL_CAPTURE_CONFIRM=record-disposable-sentinel:<workspace> \
#   DEADAIR_SENTINEL_CAPTURE_REPORT_DIR=/restricted/capture \
#   make record-sentinel-lab

Output docs/assets/sentinel-lab.gif
Output docs/assets/sentinel-lab.mp4

Set FontSize 18
Set Width 1060
Set Height 360
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 12ms
Set Shell "bash"

Hide
Type `export PATH="$PWD/bin:$PATH" PS1='$ ' && unset NO_COLOR && cd "$DEADAIR_SENTINEL_CAPTURE_REPORT_DIR" && clear`
Enter
Sleep 500ms
Type `deadair inspect --producer london-edge producer-failed.json`
Enter
Wait+Screen /Outbound connection blocks/
Show
Sleep 500ms
Screenshot docs/assets/sentinel-lab.png
Sleep 8s
Hide
Ctrl+L
Type `deadair inspect --producer london-edge producer-recovered.json`
Enter
Wait+Screen /Outbound connection blocks/
Show
Sleep 500ms
Sleep 6s
