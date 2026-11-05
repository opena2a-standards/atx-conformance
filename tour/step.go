// SPDX-License-Identifier: Apache-2.0

// Package tour is the guided tour of the ATX conformance suite: a short
// sequence of steps, each of which runs real commands from this repository,
// shows the lines of their output that matter and ends in a one-line result.
// A pre-flight runs every step unattended with the network blocked and
// records which steps are ready; the live tour shows only those.
//
// Each step is one Step value in the table Table returns. Adding a step is
// adding a row; the runner and the pre-flight need no change.
package tour

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"time"
)

// Step is one row of the tour.
type Step struct {
	Number int
	Part   int
	Title  string
	// Sentence says, in one plain sentence, what is about to happen.
	Sentence func(e *Env) string
	// Limit is the limit to say before the step runs, or nil when the step
	// has none. It may read the repository, so it can fail.
	Limit func(e *Env) (string, error)
	// Command is the command the step runs, shown dimmed.
	Command func(e *Env) string
	// Fallback is the command a presenter can type when the step does not run.
	Fallback func(e *Env) string
	// Needs reports what is missing for the step to run: a tool that is not
	// installed, or a part of the one-time setup. Nil means nothing is needed.
	Needs func(ctx context.Context, e *Env) error
	// Run runs the step's commands and collects what Trim needs.
	Run func(ctx context.Context, e *Env) (*Output, error)
	// Trim turns what Run collected into the lines worth showing and the
	// one-line result. An error means the output did not show what the step
	// is for.
	Trim func(e *Env, o *Output) (lines []string, result string, err error)
}

// Output is what a step's Run collected for its Trim.
type Output struct {
	Data any
}

// Text returns a fixed string for a Step's Sentence, Command or Fallback.
func Text(s string) func(*Env) string { return func(*Env) string { return s } }

// LimitText returns a fixed limit for a Step's Limit.
func LimitText(s string) func(*Env) (string, error) {
	return func(*Env) (string, error) { return s, nil }
}

// ErrTimeout is a step that did not finish within its timeout.
var ErrTimeout = errors.New("the step did not finish in time")

// errPanic is a step whose code panicked; the panic is in the log.
var errPanic = errors.New("the step stopped on an internal error")

// Outcome is one run of one step.
type Outcome struct {
	Lines   []string
	Result  string
	Err     error
	Elapsed time.Duration
}

// RunStep runs one step with the Env's timeout. A panic in the step's code,
// a timeout and every error end up in Outcome.Err and in the log, never on
// the screen.
func RunStep(parent context.Context, e *Env, s Step) Outcome {
	start := time.Now()
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = StepTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	type done struct {
		lines  []string
		result string
		err    error
	}
	ch := make(chan done, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				e.Log.Printf("step %d stopped on a panic: %v\n%s", s.Number, r, debug.Stack())
				ch <- done{err: errPanic}
			}
		}()
		if s.Needs != nil {
			if err := s.Needs(ctx, e); err != nil {
				ch <- done{err: err}
				return
			}
		}
		out, err := s.Run(ctx, e)
		if err != nil {
			ch <- done{err: err}
			return
		}
		lines, result, err := s.Trim(e, out)
		ch <- done{lines: lines, result: result, err: err}
	}()

	var d done
	select {
	case d = <-ch:
		if ctx.Err() == context.DeadlineExceeded {
			d = done{err: ErrTimeout}
		}
	case <-ctx.Done():
		if parent.Err() != nil {
			d = done{err: parent.Err()}
		} else {
			d = done{err: ErrTimeout}
		}
	}
	elapsed := time.Since(start)
	if d.err != nil {
		e.Log.Printf("step %d (%s) did not run: %v (after %.1f s)", s.Number, s.Title, d.err, elapsed.Seconds())
	} else {
		e.Log.Printf("step %d (%s) ran in %.1f s: %s", s.Number, s.Title, elapsed.Seconds(), d.result)
	}
	return Outcome{Lines: d.lines, Result: d.result, Err: d.err, Elapsed: elapsed}
}

// plain is an error whose text is fit for the pre-flight's one line.
type plain struct{ msg string }

func (p plain) Error() string { return p.msg }

func plainf(format string, args ...any) error { return plain{fmt.Sprintf(format, args...)} }

// Reason is the short text the pre-flight prints for a step that is hidden.
func Reason(err error, timeout time.Duration) string {
	var p plain
	switch {
	case errors.Is(err, ErrTimeout):
		return fmt.Sprintf("did not finish in %d seconds", int(timeout.Seconds()))
	case errors.As(err, &p):
		return p.msg
	default:
		return "a command failed (the log has its output)"
	}
}
