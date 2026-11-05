// SPDX-License-Identifier: Apache-2.0

package tour

import "context"

// Part2 is steps 6 and 7, which need a checkout of the delegation demo. This
// commit does not run the demo: each row holds its step's place so that the
// pre-flight prints it as hidden, with the reason, and the live tour never
// shows it. Running the demo is a change to these two rows.
func Part2() []Step {
	return []Step{
		part2Row(6, "The agent never holds the secret"),
		part2Row(7, "Revoke one agent"),
	}
}

func part2Row(number int, title string) Step {
	return Step{
		Number:   number,
		Part:     2,
		Title:    title,
		Sentence: Text(title),
		Command:  Text(""),
		Fallback: Text(""),
		Needs:    needDemo,
		Run:      func(context.Context, *Env) (*Output, error) { return nil, errPart2NotRun },
		Trim:     func(*Env, *Output) ([]string, string, error) { return nil, "", errPart2NotRun },
	}
}

var errPart2NotRun = plainf("this commit does not run the delegation demo")

// needDemo is what hides Part 2: no --demo path, or a commit that does not run
// the demo.
func needDemo(_ context.Context, e *Env) error {
	if e.Demo == "" {
		return plainf("no --demo path was given")
	}
	return errPart2NotRun
}
