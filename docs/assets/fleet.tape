# vhs tape: live fleet scan across three tenants on two backends.
# Regenerate: boot both stacks, seed (see integration/), stage fleet.json,
# then DEADAIR_DEMO_DIR=<dir> vhs docs/assets/fleet.tape
Output docs/assets/fleet.gif
Set FontSize 14
Set Width 1060
Set Height 480
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Hide
Type `export PATH="$PWD/bin:$PATH" && cd "$DEADAIR_DEMO_DIR" && clear`
Enter
Sleep 1s
Show
Type "deadair scan --fleet fleet.json"
Sleep 600ms
Enter
Sleep 3s
Sleep 6s
