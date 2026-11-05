// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// fileToken is the word part a --verifier command carries where the path of
// the fixture file goes.
const fileToken = "{file}"

// rawLimit is how many characters of a raw answer a Result keeps.
const rawLimit = 200

// outputLimit is how many bytes of a command's stdout, and of its stderr,
// the adapter keeps. The rest is read and dropped, so a verifier that
// prints without end cannot fill memory.
const outputLimit = 1 << 20

// waitDelay is how long the adapter waits for a command's output to close
// after the command was stopped or exited, for a command that started a
// child that holds its stdout open.
const waitDelay = 2 * time.Second

// splitCommand splits a --verifier command into words, without a shell.
// Words are separated by spaces, tabs and line breaks outside quotes.
// Single quotes keep everything up to the next single quote as it is.
// Double quotes keep everything up to the next double quote, where \" is a
// double quote and \\ a backslash; any other backslash is kept as it is.
// Outside quotes a backslash is an ordinary character, so a Windows path
// such as C:\tools\verify.exe is one word as written. Quotes can be joined
// to the text around them: a"b c"d is the one word ab cd.
func splitCommand(command string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(command); i++ {
		c := command[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case '\'':
			inWord = true
			end := strings.IndexByte(command[i+1:], '\'')
			if end < 0 {
				return nil, errors.New("a single quote is not closed")
			}
			cur.WriteString(command[i+1 : i+1+end])
			i += end + 1
		case '"':
			inWord = true
			closed := false
			for i++; i < len(command); i++ {
				d := command[i]
				if d == '\\' && i+1 < len(command) && (command[i+1] == '"' || command[i+1] == '\\') {
					cur.WriteByte(command[i+1])
					i++
					continue
				}
				if d == '"' {
					closed = true
					break
				}
				cur.WriteByte(d)
			}
			if !closed {
				return nil, errors.New("a double quote is not closed")
			}
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	if len(words) == 0 {
		return nil, errors.New("the command is empty")
	}
	return words, nil
}

// usesFile reports whether a split command names the fixture file.
func usesFile(argv []string) bool {
	for _, w := range argv {
		if strings.Contains(w, fileToken) {
			return true
		}
	}
	return false
}

// NewCommandAdapter returns the Adapter that runs command once per fixture,
// split into words as splitCommand splits it, with no shell. Each {file} in
// a word is replaced with the path of the fixture file; a command with no
// {file} reads the fixture's credential JSON on stdin. The command runs in
// the current directory with the environment atx-verify was given. Exit 0
// is ACCEPT, exit 1 is REJECT, and any other exit, a crash, a command that
// cannot be started or no exit within timeout is couldn't read; then
// Classify applies: when stdout is one JSON object, a "verdict" of ACCEPT,
// REJECT or ERROR decides, else a boolean "valid", else the exit code.
// Raw keeps the first 200 characters of stdout, or of stderr when stdout is
// blank; for couldn't read without a JSON verdict, Raw starts with what
// happened, for example "exit status 2".
func NewCommandAdapter(command string, timeout time.Duration) Adapter {
	argv, err := splitCommand(command)
	return &commandAdapter{argv: argv, splitErr: err, timeout: timeout}
}

type commandAdapter struct {
	argv     []string
	splitErr error
	timeout  time.Duration
}

func (a *commandAdapter) Verify(ctx context.Context, f Fixture) Result {
	if a.splitErr != nil {
		return Result{Verdict: Unreadable, Raw: firstChars("could not start: "+a.splitErr.Error(), rawLimit)}
	}
	argv := make([]string, len(a.argv))
	for i, w := range a.argv {
		argv[i] = strings.ReplaceAll(w, fileToken, f.Path)
	}
	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if !usesFile(a.argv) {
		cmd.Stdin = bytes.NewReader(f.Credential)
	}
	var stdout, stderr cappedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = waitDelay
	err := cmd.Run()

	output := stdout.buf.Bytes()
	if len(bytes.TrimSpace(output)) == 0 {
		output = stderr.buf.Bytes()
	}
	// A command stopped at the deadline ends with an error: on Windows its
	// exit code is 1, so the deadline is read before the exit code.
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return Result{Verdict: Unreadable, Raw: happened(fmt.Sprintf("no answer within %s", a.timeout), output)}
	}
	var exitErr *exec.ExitError
	code := 0
	switch {
	case err == nil, errors.Is(err, exec.ErrWaitDelay):
		code = cmd.ProcessState.ExitCode()
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case ctx.Err() != nil:
		return Result{Verdict: Unreadable, Raw: happened("stopped before it answered", output)}
	default:
		return Result{Verdict: Unreadable, Raw: happened("could not start: "+err.Error(), nil)}
	}

	fallback := Unreadable
	switch code {
	case 0:
		fallback = Accept
	case 1:
		fallback = Reject
	}
	body := stdout.buf.Bytes()
	r := Classify(fallback, body)
	r.Raw = firstChars(string(output), rawLimit)
	if r.Verdict == Unreadable && !jsonDecides(body) {
		what := fmt.Sprintf("exit status %d", code)
		if code < 0 {
			what = "ended without an exit status: " + err.Error()
		}
		r.Raw = happened(what, output)
	}
	return r
}

// jsonDecides reports whether body carries a JSON verdict that Classify
// reads, so the exit code did not decide.
func jsonDecides(body []byte) bool {
	return Classify(Accept, body).Verdict == Classify(Reject, body).Verdict
}

// happened is a Raw for couldn't read: what happened, then the first
// characters of the output, if any.
func happened(what string, output []byte) string {
	if s := strings.TrimSpace(string(output)); s != "" {
		what += ": " + s
	}
	return firstChars(what, rawLimit)
}

// cappedBuffer keeps the first outputLimit bytes written to it and drops
// the rest, reporting every write as complete so the command is not
// stopped by a short write.
type cappedBuffer struct {
	buf bytes.Buffer
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := outputLimit - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}
