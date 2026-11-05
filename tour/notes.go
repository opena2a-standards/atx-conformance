// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// NotesForm is a three-line example of a --notes file, which the flag help
// prints.
const NotesForm = `1: The answer key is a file anyone can read.
3:
  - Say the limit before pressing Enter.`

// Notes holds a presenter's lines for each step number.
type Notes map[int][]string

// ParseNotes reads the small form NotesForm shows, a subset of YAML:
//
//	# a comment line, or a blank line, is skipped
//	3: one line for step 3            (repeating "3:" adds a line)
//	step 3: the same                  ("step" is optional)
//	3:                                (a key alone opens a list)
//	  - a line for step 3
//	  - another line
//
// A value may be wrapped in single or double quotes. Anything else is an
// error that names its line number, so a mistake shows at rehearsal and not
// on stage.
func ParseNotes(r io.Reader) (Notes, error) {
	notes := Notes{}
	scanner := bufio.NewScanner(r)
	current := 0
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimRight(scanner.Text(), " \t\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indented := raw != strings.TrimLeft(raw, " \t")
		if indented {
			if current == 0 {
				return nil, fmt.Errorf("line %d: an indented line needs a step number above it", lineNo)
			}
			text := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			if text == "" {
				return nil, fmt.Errorf("line %d: a list item has no text", lineNo)
			}
			notes[current] = append(notes[current], unquote(text))
			continue
		}
		key, value, found := strings.Cut(trimmed, ":")
		if !found {
			return nil, fmt.Errorf("line %d: expected \"<step number>: <text>\"", lineNo)
		}
		key = strings.Trim(strings.TrimSpace(key), `"'`)
		if strings.HasPrefix(strings.ToLower(key), "step") {
			key = strings.TrimSpace(key[len("step"):])
		}
		number, err := strconv.Atoi(key)
		if err != nil || number < 1 {
			return nil, fmt.Errorf("line %d: %q is not a step number", lineNo, key)
		}
		current = number
		value = strings.TrimSpace(value)
		if value == "" || value == "|" {
			continue
		}
		notes[number] = append(notes[number], unquote(value))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return notes, nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
