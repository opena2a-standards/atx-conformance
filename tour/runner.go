// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Key is what a presenter pressed.
type Key int

// The keys the tour reads.
const (
	KeyNext Key = iota
	KeyRepeat
	KeyQuit
)

// Keys reads key presses from the presenter's input. In single-key mode
// (a terminal in cbreak mode) one byte is one key; otherwise one line is one
// key, so piped Enter presses drive the tour. End of input is q.
type Keys struct {
	ch     chan string
	single bool
	drain  bool
}

// NewKeys starts reading r. single is one byte per key; drain discards keys
// pressed while a step was running, so a stray key never skips a step.
func NewKeys(r io.Reader, single, drain bool) *Keys {
	k := &Keys{ch: make(chan string, 64), single: single, drain: drain}
	go func() {
		defer close(k.ch)
		br := bufio.NewReader(r)
		for {
			if single {
				b, err := br.ReadByte()
				if err != nil {
					return
				}
				k.ch <- string(b)
				continue
			}
			line, err := br.ReadString('\n')
			if line != "" || err == nil {
				k.ch <- strings.TrimSpace(line)
			}
			if err != nil {
				return
			}
		}
	}()
	return k
}

// Next waits for a key the tour knows and ignores every other key. A
// cancelled ctx (Ctrl-C) and the end of input are q.
func (k *Keys) Next(ctx context.Context) Key {
	if k.drain {
		for pending := true; pending; {
			select {
			case _, ok := <-k.ch:
				if !ok {
					return KeyQuit
				}
			default:
				pending = false
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return KeyQuit
		case s, ok := <-k.ch:
			if !ok {
				return KeyQuit
			}
			switch strings.ToLower(s) {
			case "", "\n", "\r":
				return KeyNext
			case "r":
				return KeyRepeat
			case "q":
				return KeyQuit
			}
		}
	}
}

// Tour is the live tour.
type Tour struct {
	Env    *Env
	Steps  []Step
	Notes  Notes
	Screen *Screen
	Keys   *Keys
}

// failLine is what the screen shows for a step that did not run.
const failLine = "This step didn't run. Here's the command instead:"

// formLimit is the limit said before the first step: what a verifier in the
// room can read of these fixtures.
const formLimit = "These fixtures are native ATX credentials. A verifier that reads JWT or " +
	"W3C credentials cannot parse them; the kit in this repository records that as " +
	"couldn't read, which is a result. The jws and vc forms are reserved for a later release."

// Show runs the steps the state marks ready, in table order, one per key
// press. It returns the process exit code.
func (t *Tour) Show(ctx context.Context, st *State) int {
	ready := st.ReadyNumbers()
	var steps []Step
	for _, s := range t.Steps {
		if ready[s.Number] {
			steps = append(steps, s)
		}
	}
	scr := t.Screen
	if len(steps) == 0 {
		scr.Para("", "No step passed the pre-flight, so the tour has nothing to show. "+
			"Run --check to see each step's reason.")
		return 1
	}
	var numbers []string
	for _, s := range steps {
		numbers = append(numbers, fmt.Sprint(s.Number))
	}
	scr.Rule()
	scr.Title("ATX conformance: a guided tour")
	scr.Printf("Clone: atx-conformance at %s", shortCommit(t.Env.Commit))
	scr.Printf("Steps: %s (the pre-flight of %s passed them)", strings.Join(numbers, " "), st.CheckedAt)
	scr.Blank()
	scr.Labeled("Said first: ", formLimit, "")
	scr.Blank()
	scr.Printf("Enter: next step    r: repeat a step    q: quit")
	if steps[0].UsesDemo {
		t.Env.StartDemo()
	}
	if t.Keys.Next(ctx) == KeyQuit {
		return t.stopped(ctx)
	}
	for i := 0; i < len(steps); {
		ok := t.showStep(ctx, steps[i])
		if steps[i].UsesDemo && !ok {
			t.Env.StopDemo()
		}
		if ctx.Err() != nil {
			return t.stopped(ctx)
		}
		// The demo starts while the presenter is still on the step before
		// the first step that uses it.
		if i+1 < len(steps) && steps[i+1].UsesDemo {
			t.Env.StartDemo()
		}
		if i == len(steps)-1 {
			scr.Printf("[Enter] end   [r] repeat   [q] quit")
		} else {
			scr.Printf("[Enter] next   [r] repeat   [q] quit")
		}
		switch t.Keys.Next(ctx) {
		case KeyQuit:
			return t.stopped(ctx)
		case KeyRepeat:
			continue
		}
		if steps[i].UsesDemo && !demoAfter(steps[i+1:]) {
			t.Env.StopDemo()
		}
		i++
	}
	t.Env.StopDemo()
	scr.Rule()
	scr.Printf("End of the tour.")
	return 0
}

// stopped ends the tour early: q, the end of input, or Ctrl-C (exit 130).
func (t *Tour) stopped(ctx context.Context) int {
	t.Env.StopDemo()
	t.Screen.Blank()
	t.Screen.Printf("Tour stopped.")
	if ctx.Err() != nil {
		return 130
	}
	return 0
}

// showStep shows one step and reports whether it ran.
func (t *Tour) showStep(ctx context.Context, s Step) bool {
	scr, e := t.Screen, t.Env
	scr.Rule()
	scr.Title(fmt.Sprintf("Step %d. %s", s.Number, s.Title))
	scr.Blank()
	scr.Para("", s.Sentence(e))
	if s.Limit != nil {
		limit, err := s.Limit(e)
		if err != nil {
			e.Log.Printf("step %d: its limit could not be read: %v", s.Number, err)
			t.fail(s, false)
			return false
		}
		scr.Blank()
		scr.Labeled("Said first: ", limit, "")
	}
	for _, note := range t.Notes[s.Number] {
		scr.Note(note)
	}
	scr.Blank()
	scr.Command(s.Command(e))
	scr.Running()
	out := RunStep(ctx, e, s)
	scr.DoneRunning()
	if ctx.Err() != nil {
		return false
	}
	if out.Err != nil {
		t.fail(s, errors.Is(out.Err, ErrTimeout))
		return false
	}
	for _, line := range out.Lines {
		scr.Output(line)
	}
	scr.Blank()
	scr.Result(true, out.Result)
	scr.Blank()
	return true
}

// fail shows the fallback command and nothing of the error, which is in the log.
func (t *Tour) fail(s Step, timedOut bool) {
	scr := t.Screen
	if timedOut {
		scr.Printf("  It did not finish in %d seconds.", int(t.Env.Timeout.Seconds()))
	}
	scr.Result(false, failLine)
	scr.Command(s.Fallback(t.Env))
	scr.Blank()
}
