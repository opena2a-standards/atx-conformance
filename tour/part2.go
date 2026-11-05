// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Part2 is steps 6 and 7. They run against a checkout of the delegation demo
// given with --demo: the tour starts the demo's launcher once, before step 6,
// and stops it when step 7 ends. Without --demo both are hidden.
func Part2() []Step {
	return []Step{stepSecret(), stepRevoke()}
}

// The commands of Part 2. Each runs as `bash -c <command>` under the macOS
// sandbox profile that refuses every outbound connection except to loopback.
// $DEMO_TMP (the TMPDIR the tour made for the demo), $PORT (the demo's port)
// and $RUN (the demo's live run directory) reach them as environment
// variables.
const (
	cmdScenario1 = `curl -sS -m 25 -o "$DEMO_TMP/step6.json" -w 'http %{http_code}\n' -X POST ` +
		`-H 'Content-Type: application/json' --data '{"scenario":"1"}' "http://127.0.0.1:$PORT/api/run"`
	cmdScenario3 = `curl -sS -m 25 -o "$DEMO_TMP/step7.json" -w 'http %{http_code}\n' -X POST ` +
		`-H 'Content-Type: application/json' --data '{"scenario":"3"}' "http://127.0.0.1:$PORT/api/run"`
	cmdFindRun     = `RUN=$(ls -td "$DEMO_TMP"/bank-demo-run-* | head -1)`
	cmdListAgent   = `ls "$RUN/agent-b-billpay"`
	cmdSearchAgent = `grep -rIl -i -e password -e customer.a -e customer.b "$RUN/agent-b-billpay"`
	cmdScenarios   = "npm run scenarios"
	cmdSearchAfter = `D=$(ls -td "$TMPDIR"/bank-demo-run-* | head -1); ls "$D/agent-b-billpay"; ` +
		`grep -rIl -i -e password -e customer.a -e customer.b "$D/agent-b-billpay" || echo "no match"`
)

// needDemo is what every step of Part 2 needs: a --demo path, the tools its
// commands run, and the demo running. The first start checks the checkout and
// gives a reason a presenter can act on when it is not ready.
func needDemo(ctx context.Context, e *Env) error {
	if e.Demo == "" {
		return errNoDemo
	}
	if !hasLauncher(e.Demo) {
		return errNotDemo
	}
	if err := needBash(e); err != nil {
		return err
	}
	if !e.Has("curl") {
		return plainf("curl is not installed")
	}
	_, err := e.demoRunning(ctx)
	return err
}

// demoFallback is the command a presenter can type in the demo checkout: the
// demo's own text runner, which shows both paths of every scenario.
func demoFallback(e *Env) string {
	dir := "<demo checkout>"
	if e.Demo != "" {
		dir = shellQuote(e.Demo)
	}
	return "cd " + dir + " && " + cmdScenarios
}

// runDemoCmd runs one command of Part 2 in the demo's directory.
func (e *Env) runDemoCmd(ctx context.Context, d *demo, command string, vars ...string) (string, error) {
	vars = append([]string{"DEMO_TMP=" + d.tmp, "PORT=" + strconv.Itoa(d.port)}, vars...)
	return e.runIn(exec.CommandContext(ctx, "bash", "-c", command), d.tmp, "the demo's directory", sandboxLoopback, vars...)
}

// runScenario posts one scenario to the demo and reads its answer.
func (e *Env) runScenario(ctx context.Context, d *demo, command, file string) (demoAnswer, error) {
	var a demoAnswer
	out, err := e.runDemoCmd(ctx, d, command)
	if err != nil || strings.TrimSpace(out) != "http 200" {
		return a, plainf("the demo did not answer the scenario (the log has curl's output)")
	}
	b, err := fs.ReadFile(os.DirFS(d.tmp), file)
	if err == nil {
		err = json.Unmarshal(b, &a)
	}
	if err != nil {
		e.Log.Printf("the demo's answer in %s could not be read: %v", file, err)
		return a, plainf("the demo's answer could not be read")
	}
	return a, nil
}

// demoAnswer is the part of the demo's answer to POST /api/run the steps read.
type demoAnswer struct {
	Sandbox struct {
		Applied bool `json:"applied"`
	} `json:"sandbox"`
	Steps map[string]map[string]demoPath `json:"steps"`
}

// demoPath is one path of one scenario: A is the password path, B the grant
// path.
type demoPath struct {
	BankSaw      string `json:"bankSaw"`
	BankDecision string `json:"bankDecision"`
	Reason       string `json:"reason"`
	Effects      []struct {
		Who     string `json:"who"`
		Outcome string `json:"outcome"`
	} `json:"effects"`
}

func (a demoAnswer) path(step, path string) demoPath { return a.Steps[step][path] }

// liveRun is the demo's live run directory: the one that still holds the
// grant path agent's broker token. A run the demo stopped is scrubbed of it.
func liveRun(tmp string) (string, error) {
	runs, err := fs.Glob(os.DirFS(tmp), "bank-demo-run-*/agent-b-billpay/broker.token")
	if err != nil || len(runs) != 1 {
		return "", plainf("the demo's live run directory was not found")
	}
	run, _, _ := strings.Cut(runs[0], "/")
	return tmp + string(os.PathSeparator) + run, nil
}

// exitCode is a command's exit status, or -1 when it did not exit.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// ---- step 6: the agent never holds the secret ---------------------------------

type secretData struct {
	Answer  demoAnswer
	Listing []string
	Search  int // grep's exit status: 1 is no match
}

func stepSecret() Step {
	shown := cmdScenario1 + "\n" + cmdFindRun + "\n" + cmdListAgent + "\n" + cmdSearchAgent
	return Step{
		Number:   6,
		Part:     2,
		Title:    "The agent never holds the secret",
		UsesDemo: true,
		Sentence: Text("The mock bank pays the same bill once with the customer's password and once " +
			"under a grant; then the tour lists the grant path agent's directory and searches it " +
			"for a password or the customer's sign-in name."),
		Limit: LimitText("The agent's directory holds the broker token; revoking a grant means " +
			"restarting the broker."),
		Command: Text(shown),
		Fallback: func(e *Env) string {
			return demoFallback(e) + "\n" + cmdSearchAfter
		},
		Needs: needDemo,
		Run: func(ctx context.Context, e *Env) (*Output, error) {
			d, err := e.demoRunning(ctx)
			if err != nil {
				return nil, err
			}
			a, err := e.runScenario(ctx, d, cmdScenario1, "step6.json")
			if err != nil {
				return nil, err
			}
			run, err := liveRun(d.tmp)
			if err != nil {
				return nil, err
			}
			listing, err := e.runDemoCmd(ctx, d, cmdListAgent, "RUN="+run)
			if err != nil {
				return nil, plainf("the agent's directory could not be listed")
			}
			_, err = e.runDemoCmd(ctx, d, cmdSearchAgent, "RUN="+run)
			search := exitCode(err)
			if err := e.checkEgress(d); err != nil {
				return nil, err
			}
			return &Output{Data: secretData{Answer: a, Listing: strings.Fields(listing), Search: search}}, nil
		},
		Trim: func(_ *Env, o *Output) ([]string, string, error) {
			d := o.Data.(secretData)
			a := d.Answer
			setupA, billA := a.path("setup", "A"), a.path("1", "A")
			approveB, billB := a.path("approve", "B"), a.path("1", "B")
			switch {
			case !a.Sandbox.Applied:
				return nil, "", plainf("the demo's parts did not run in their own sandboxes")
			case setupA.BankSaw != "Customer A" || billA.BankDecision != "paid" ||
				billB.BankDecision != "paid" || billB.BankSaw != "Bill pay agent" ||
				setupA.Reason == "" || billA.Reason == "" || approveB.Reason == "" || billB.Reason == "":
				return nil, "", plainf("the demo's answer to scenario 1 is not the one this step was measured with")
			case !holdsAll(d.Listing, "atx.json", "grant.json", "broker.token"):
				return nil, "", plainf("the agent's directory does not hold its credential, grant name and broker token")
			case d.Search == 0:
				return nil, "", plainf("the search found a password or a sign-in name in the agent's directory (the log names the file)")
			case d.Search != 1:
				return nil, "", plainf("the search of the agent's directory did not finish cleanly")
			}
			return []string{
				"Password path: " + setupA.Reason,
				"Password path, a normal bill: " + billA.Reason,
				"Grant path: " + approveB.Reason,
				"Grant path, a normal bill: " + billB.Reason + " The bank saw: " + billB.BankSaw + ".",
				"The grant path agent's directory holds: " + strings.Join(d.Listing, " "),
				"Search for a password or the customer's sign-in name in that directory: no match",
			}, "No password or customer sign-in name in the grant path agent's directory.", nil
		},
	}
}

func holdsAll(have []string, want ...string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

// ---- step 7: revoke one agent ------------------------------------------------

// revokeOutcomes are the three facts of step 7, on the grant path: one agent
// cut off, the customer's login and the other agent still working.
var revokeOutcomes = map[string]string{
	"Bill pay agent": "refused by the broker",
	"Budget agent":   "read the balance",
	"Customer B":     "kept working",
}

func stepRevoke() Step {
	return Step{
		Number:   7,
		Part:     2,
		Title:    "Revoke one agent",
		UsesDemo: true,
		Sentence: Text("On a fresh bank, the customer withdraws one agent's consent on the grant path " +
			"and changes the password on the password path; the bank's answer shows who keeps " +
			"working after each."),
		Limit: LimitText("ATX is bearer today: a copy of an agent's credential, presented with its " +
			"grant name by a second holder, is accepted as that agent."),
		Command:  Text(cmdScenario3),
		Fallback: demoFallback,
		Needs:    needDemo,
		Run: func(ctx context.Context, e *Env) (*Output, error) {
			d, err := e.demoRunning(ctx)
			if err != nil {
				return nil, err
			}
			a, err := e.runScenario(ctx, d, cmdScenario3, "step7.json")
			if err != nil {
				return nil, err
			}
			if err := e.checkEgress(d); err != nil {
				return nil, err
			}
			return &Output{Data: a}, nil
		},
		Trim: func(_ *Env, o *Output) ([]string, string, error) {
			a := o.Data.(demoAnswer)
			pw, grant := a.path("3", "A"), a.path("3", "B")
			if !a.Sandbox.Applied {
				return nil, "", plainf("the demo's parts did not run in their own sandboxes")
			}
			seen := map[string]string{}
			for _, ef := range grant.Effects {
				seen[ef.Who] = ef.Outcome
			}
			same := len(grant.Effects) == len(revokeOutcomes)
			for who, outcome := range revokeOutcomes {
				same = same && seen[who] == outcome
			}
			if grant.BankDecision != "consent withdrawn" || !same || pw.Reason == "" || grant.Reason == "" || len(pw.Effects) == 0 {
				return nil, "", plainf("the demo's answer to scenario 3 is not the one this step was measured with")
			}
			lines := []string{"Password path: " + pw.Reason}
			for _, ef := range pw.Effects {
				lines = append(lines, "  "+ef.Who+": "+ef.Outcome)
			}
			lines = append(lines, "Grant path: "+grant.Reason)
			for _, ef := range grant.Effects {
				lines = append(lines, "  "+ef.Who+": "+ef.Outcome)
			}
			return lines, "One agent cut off; the customer's login and the other agent kept working.", nil
		},
	}
}
