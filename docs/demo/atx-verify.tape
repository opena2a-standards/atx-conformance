# The front door of atx-conformance: the README's first command, run in an empty directory with
# nothing cloned. Render it with docs/demo/record-atx-verify.sh, which runs this tape in the image
# docs/demo/docker/Dockerfile builds and writes docs/demo/atx-verify.json.
# Pace: front-door
#
# The command is longer than 72 characters, so it is typed on two lines joined by a backslash
# continuation (P1). The verifier prints more lines than the 28 rows hold, so the hold is on the
# last screen, which ends with the summary line; docs/demo/atx-verify-capture.txt has every line.
# Each hold after Enter is sized from docs/demo/atx-verify.narration.json (P3), and the record
# script refuses to write the sidecar when a hold is shorter than that or longer than 12 s.
#
# The hidden setup enters an empty directory and runs the command once with its output discarded,
# so the module download is finished before anything is shown; then it clears the screen.
Output docs/demo/atx-verify.gif
Output docs/demo/out/atx-verify.mp4
Require go
Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Columns 110
Set Rows 28
Set Theme "Catppuccin Mocha"
Set TypingSpeed 120ms
Set Padding 20
Set Framerate 10
Set CursorBlink false

Hide
Type@10ms "mkdir -p /work/front-door && cd /work/front-door && go run github.com/opena2a-standards/atx-conformance/cmd/atx-verify@latest --version >/dev/null 2>&1; clear"
Enter
Wait@180s
Show
Sleep 1s
# step: s1
Type `go run github.com/opena2a-standards/\`
Sleep 800ms
Enter
Type "atx-conformance/cmd/atx-verify@latest"
Sleep 800ms
Enter
Wait@60s
Screenshot docs/demo/atx-verify-s1.png
Sleep 10s
# step: s2
Type "echo $?"
Sleep 800ms
Enter
Wait@10s
Screenshot docs/demo/atx-verify-s2.png
Sleep 5s
