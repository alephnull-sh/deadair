# vhs tape: credential-free first run using the real embedded demo.
# Regenerate from the repository root:
#   make build
#   vhs docs/assets/demo.tape
Output docs/assets/demo.gif

Set FontSize 14
Set Width 1060
Set Height 440
Set Padding 14
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type `export PATH="$PWD/bin:$PATH" && clear`
Enter
Type "deadair demo"
Show
Sleep 500ms
Enter
Sleep 5s
