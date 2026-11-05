// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Width is the number of columns every line the tour prints fits in.
const Width = 80

// The escape sequences the tour uses, and only when color is on.
const (
	escBold  = "\x1b[1m"
	escDim   = "\x1b[2m"
	escNote  = "\x1b[36m" // the second color: presenter notes
	escGood  = "\x1b[32m"
	escBad   = "\x1b[33m"
	escReset = "\x1b[0m"
	escClear = "\r\x1b[2K"
)

// ColorEnabled reports whether the tour may print escape sequences: only to a
// terminal, never when NO_COLOR is set to any non-empty value
// (https://no-color.org), and never to a terminal that calls itself dumb.
func ColorEnabled(getenv func(string) string, terminal bool) bool {
	if getenv("NO_COLOR") != "" {
		return false
	}
	if getenv("TERM") == "dumb" {
		return false
	}
	return terminal
}

// Screen writes lines of at most Width columns. With color off it writes no
// escape sequence at all.
type Screen struct {
	w     io.Writer
	color bool
}

// NewScreen returns a Screen writing to w.
func NewScreen(w io.Writer, color bool) *Screen {
	return &Screen{w: w, color: color}
}

func (s *Screen) paint(esc, text string) string {
	if !s.color || text == "" {
		return text
	}
	return esc + text + escReset
}

func (s *Screen) println(text string) {
	_, _ = io.WriteString(s.w, text+"\n")
}

// Blank writes an empty line.
func (s *Screen) Blank() { s.println("") }

// Rule writes a full-width separator.
func (s *Screen) Rule() { s.println(s.paint(escDim, strings.Repeat("-", Width))) }

// Title writes a bold line, clipped to Width.
func (s *Screen) Title(text string) { s.println(s.paint(escBold, Clip(text, Width))) }

// Para writes prose wrapped at Width, each line indented by indent.
func (s *Screen) Para(indent, text string) {
	for _, line := range Wrap(text, Width-utf8.RuneCountInString(indent)) {
		s.println(indent + line)
	}
}

// Labeled writes prose wrapped at Width whose first line starts with label
// and whose next lines are indented to line up under the text.
func (s *Screen) Labeled(label, text, esc string) {
	pad := strings.Repeat(" ", utf8.RuneCountInString(label))
	for i, line := range Wrap(text, Width-utf8.RuneCountInString(label)) {
		lead := pad
		if i == 0 {
			lead = label
		}
		s.println(s.paint(esc, lead+line))
	}
}

// Command writes a command, dimmed, one shell line per screen line. A line
// longer than Width is broken at spaces with a trailing backslash, so what is
// shown can still be pasted into a shell.
func (s *Screen) Command(cmd string) {
	for _, line := range strings.Split(cmd, "\n") {
		for _, part := range breakCommand("  $ ", "      ", line, Width) {
			s.println(s.paint(escDim, part))
		}
	}
}

// Output writes one output line, indented. A line longer than Width is
// wrapped at spaces, its next lines indented further, so no output is cut.
func (s *Screen) Output(line string) {
	lead := "  " + leadingSpace(line)
	body := strings.TrimLeft(line, " ")
	if utf8.RuneCountInString(lead+body) <= Width {
		s.println(strings.TrimRight(lead+body, " "))
		return
	}
	for i, part := range Wrap(body, Width-utf8.RuneCountInString(lead)-2) {
		if i == 0 {
			s.println(lead + part)
			continue
		}
		s.println(lead + "  " + part)
	}
}

func leadingSpace(s string) string { return s[:len(s)-len(strings.TrimLeft(s, " "))] }

// Note writes a presenter note in the second color.
func (s *Screen) Note(text string) { s.Labeled("  > ", text, escNote) }

// Result writes the one-line result of a step.
func (s *Screen) Result(ok bool, text string) {
	esc := escGood
	if !ok {
		esc = escBad
	}
	s.println(s.paint(esc, Clip("  "+text, Width)))
}

// Running writes the single "running" line. With color on it is erased by
// DoneRunning; with color off it stays, so the plain text never carries an
// escape sequence.
func (s *Screen) Running() {
	if s.color {
		_, _ = io.WriteString(s.w, s.paint(escDim, "  running"))
		return
	}
	s.println("  running")
}

// DoneRunning erases the running line when color is on.
func (s *Screen) DoneRunning() {
	if s.color {
		_, _ = io.WriteString(s.w, escClear)
	}
}

// Printf writes one formatted line, clipped to Width.
func (s *Screen) Printf(format string, args ...any) {
	s.println(Clip(fmt.Sprintf(format, args...), Width))
}

// Clip cuts text to at most width columns, ending in "..." when it cut.
func Clip(text string, width int) string {
	text = strings.TrimRight(text, " \t\r")
	if utf8.RuneCountInString(text) <= width {
		return text
	}
	runes := []rune(text)
	return string(runes[:width-3]) + "..."
}

// Wrap breaks prose into lines of at most width columns at spaces. A word
// longer than width is clipped.
func Wrap(text string, width int) []string {
	var lines []string
	var line strings.Builder
	for _, word := range strings.Fields(text) {
		n := utf8.RuneCountInString(word)
		switch {
		case line.Len() == 0:
			line.WriteString(Clip(word, width))
		case utf8.RuneCountInString(line.String())+1+n <= width:
			line.WriteString(" " + word)
		default:
			lines = append(lines, line.String())
			line.Reset()
			line.WriteString(Clip(word, width))
		}
	}
	if line.Len() > 0 {
		lines = append(lines, line.String())
	}
	return lines
}

// breakCommand splits one shell line into screen lines of at most width
// columns, breaking at spaces and ending each broken line with " \".
func breakCommand(first, next, line string, width int) []string {
	words := strings.Fields(line)
	var out []string
	cur := first
	empty := true
	for _, w := range words {
		candidate := cur + w
		if !empty {
			candidate = cur + " " + w
		}
		// Leave room for the " \" a broken line ends with.
		if !empty && utf8.RuneCountInString(candidate) > width-2 {
			out = append(out, cur+" \\")
			cur = next + w
			continue
		}
		cur = candidate
		empty = false
	}
	out = append(out, Clip(cur, width))
	return out
}
