// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// StateFile is the name of the pre-flight's state file in the state directory.
const StateFile = "preflight-state.json"

// The status a step gets from the pre-flight.
const (
	Ready  = "ready"
	Hidden = "hidden"
)

// State is what the pre-flight writes and the live tour reads: which steps
// may be shown, for which clone and commit.
type State struct {
	Tool      string      `json:"tool"`
	CheckedAt string      `json:"checkedAt"`
	Repo      string      `json:"repo"`
	Commit    string      `json:"commit"`
	Demo      string      `json:"demo,omitempty"`
	Seconds   float64     `json:"seconds"`
	Steps     []StepState `json:"steps"`
}

// StepState is one step's pre-flight result.
type StepState struct {
	Number  int     `json:"number"`
	Title   string  `json:"title"`
	Status  string  `json:"status"`
	Reason  string  `json:"reason,omitempty"`
	Seconds float64 `json:"seconds"`
}

// ReadyNumbers lists the steps the state marks ready.
func (s *State) ReadyNumbers() map[int]bool {
	ready := map[int]bool{}
	for _, st := range s.Steps {
		if st.Status == Ready {
			ready[st.Number] = true
		}
	}
	return ready
}

// Preflight runs every step unattended, with the network blocked for every
// command, prints one line per step and returns the state to save.
func Preflight(ctx context.Context, e *Env, steps []Step, scr *Screen) *State {
	start := time.Now()
	st := &State{Tool: "atx-tour", Repo: e.Repo, Commit: e.Commit, Demo: e.Demo}
	scr.Title("Pre-flight: every step, run unattended with the network blocked")
	scr.Printf("Clone: atx-conformance at %s", shortCommit(e.Commit))
	scr.Labeled("Network: blocked by ", e.NetworkBlock(), "")
	scr.Blank()
	e.Log.Printf("pre-flight of %s at %s; network blocked by %s", e.Repo, e.Commit, e.NetworkBlock())
	for _, s := range steps {
		reason := ""
		var limitErr error
		if s.Limit != nil {
			_, limitErr = s.Limit(e)
		}
		out := RunStep(ctx, e, s)
		switch {
		case out.Err != nil:
			reason = Reason(out.Err, e.Timeout)
		case limitErr != nil:
			e.Log.Printf("step %d: its limit could not be read: %v", s.Number, limitErr)
			reason = "the limit to say first could not be read from the repository"
		}
		status := Ready
		if reason != "" {
			status = Hidden
		}
		st.Steps = append(st.Steps, StepState{
			Number: s.Number, Title: s.Title, Status: status, Reason: reason,
			Seconds: round1(out.Elapsed.Seconds()),
		})
		label := fmt.Sprintf("step %d  %-7s ", s.Number, status)
		if status == Ready {
			scr.Labeled(label, fmt.Sprintf("%s (%.1f s)", s.Title, out.Elapsed.Seconds()), "")
		} else {
			scr.Labeled(label, s.Title+": "+reason, "")
		}
	}
	st.Seconds = round1(time.Since(start).Seconds())
	st.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	ready := 0
	for _, s := range st.Steps {
		if s.Status == Ready {
			ready++
		}
	}
	scr.Blank()
	scr.Printf("%d ready, %d hidden, in %.1f s. Only ready steps appear in the tour.", ready, len(st.Steps)-ready, st.Seconds)
	return st
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// SaveState writes the state file into dir.
func SaveState(dir string, st *State) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, StateFile))
}

// errNoState is a state directory with no pre-flight result in it.
var errNoState = errors.New("no pre-flight result")

// LoadState reads the state file from dir.
func LoadState(dir string) (*State, error) {
	b, err := fs.ReadFile(os.DirFS(dir), StateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNoState
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// StateMatches reports whether a saved state was made for this clone at
// this commit; a state for another clone or commit says nothing about this one.
func StateMatches(st *State, e *Env) (bool, string) {
	switch {
	case st.Repo != e.Repo:
		return false, "The last pre-flight checked a different clone"
	case st.Commit != e.Commit:
		return false, fmt.Sprintf("The last pre-flight checked commit %s, and this clone is at %s",
			shortCommit(st.Commit), shortCommit(e.Commit))
	case st.Demo != e.Demo:
		return false, "The last pre-flight ran with a different --demo"
	}
	return true, ""
}
