# The README animation, recorded from the real demo.
#
# Regenerate with:  vhs demos/push-broker/demo.tape
#
# This runs demos/push-broker/demo.sh unmodified. Every frame is that script's
# real output against a real repository — nothing here retypes or stages it.

Output docs/assets/push-broker-demo.gif

Require bash
Require git

Set Shell bash
Set FontSize 13
Set Width 1100
Set Height 720
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms

# Setup the viewer does not need to watch: a clean prompt, and the pacing
# that gives each scene time to be read.
Hide
Type "export PS1='$ ' DEMO_PAUSE=1.2 && clear"
Enter
Sleep 500ms
Show

Type "./demos/push-broker/demo.sh"
Sleep 600ms
Enter

# Scenes 1 and 2, up to the confirmation prompt.
Sleep 9s

# The decision a human makes.
Type "y"
Sleep 700ms
Enter

# The push, the receipt, the refused shape, the audit count.
Sleep 13s
