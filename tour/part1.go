// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"math/bits"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The commands Part 1 runs. Each runs as `bash -c <command>` in the clone's
// root, so the text shown on the screen is the text that runs. $DIR and $PY
// reach a command as environment variables.
const (
	cmdManifestShasum    = "shasum -a 256 -c MANIFEST.sha256"
	cmdManifestSha256sum = "sha256sum -c MANIFEST.sha256"
	cmdGoAll             = "go run ./verifiers/go fixtures"
	cmdPythonAll         = "verifiers/python/.venv/bin/python3 verifiers/python/verify.py fixtures"
	cmdRefuse            = "go run ./verifiers/go fixtures/expired.json fixtures/wrong-issuer.json fixtures/v1_1-hybrid-mldsa-tampered.json"
	cmdIssue             = `"$PY" tour/issuer/issue_atx.py "$DIR"`
	cmdGoDir             = `go run ./verifiers/go "$DIR"`
	cmdPythonDir         = `"$PY" verifiers/python/verify.py "$DIR"`
	cmdGate              = ". verifiers/python/.venv/bin/activate && cd jcs-vectors && ./run-agreement.sh"
	cmdPythonImports     = `verifiers/python/.venv/bin/python3 -c "import cryptography, dilithium_py"`
	cmdGoModules         = "go list -deps ./verifiers/go > /dev/null && cd jcs-vectors && go list -deps ./check > /dev/null"

	venvPython = "verifiers/python/.venv/bin/python3"
	issuerPath = "tour/issuer/issue_atx.py"
)

// The fixtures step 3 shows, in the order it shows them, and the valid
// fixture the forged one is compared with.
const (
	fixtureExpired   = "fixtures/expired.json"
	fixtureUntrusted = "fixtures/wrong-issuer.json"
	fixtureForged    = "fixtures/v1_1-hybrid-mldsa-tampered.json"
	fixtureHybrid    = "fixtures/v1_1-baseline-valid-hybrid.json"
)

// Part1 is steps 1 to 5: they need only this repository.
func Part1() []Step {
	return []Step{stepAnswerKey(), stepTwoVerifiers(), stepRefuse(), stepIssue(), stepSameBytes()}
}

// needBash is the first need of every step: each command runs under bash.
func needBash(e *Env) error {
	if !e.Has("bash") {
		return plainf("bash is not installed")
	}
	return nil
}

// needGo is Go on PATH and the modules the verifier builds from in the
// module cache, which --setup downloads.
func needGo(ctx context.Context, e *Env) error {
	if err := needBash(e); err != nil {
		return err
	}
	if !e.Has("go") {
		return plainf("Go is not installed")
	}
	return e.goModulesReady(ctx)
}

// pythonInstalled reports whether this laptop has Python at all.
func pythonInstalled(e *Env) bool { return e.Has("python3") }

// ---- reading the repository ------------------------------------------------

type fixtureFile struct {
	Expected struct {
		VerifyResult   string `json:"verifyResult"`
		RejectCategory string `json:"rejectCategory"`
	} `json:"expected"`
	VerifierState struct {
		Clock          string   `json:"clockRfc3339"`
		TrustedIssuers []string `json:"trustedIssuers"`
	} `json:"verifierState"`
	ATX json.RawMessage `json:"atx"`
}

func readJSON(fsys fs.FS, name string, v any) error {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func readFixture(fsys fs.FS, name string) (fixtureFile, error) {
	var f fixtureFile
	err := readJSON(fsys, name, &f)
	return f, err
}

func verdict(result, category string) string {
	if category == "" {
		return result
	}
	return result + " " + category
}

// atxMembers flattens a credential into member path -> canonical value, so
// two credentials can be compared member by member.
func atxMembers(raw json.RawMessage) (map[string]string, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, child := range t {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, child)
			}
		case []any:
			for i, child := range t {
				walk(fmt.Sprintf("%s[%d]", prefix, i), child)
			}
		default:
			b, _ := json.Marshal(t)
			out[prefix] = string(b)
		}
	}
	walk("", v)
	return out, nil
}

func differingMembers(a, b map[string]string) []string {
	var diff []string
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			diff = append(diff, k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			diff = append(diff, k)
		}
	}
	sort.Strings(diff)
	return diff
}

// ---- reading verifier output ------------------------------------------------

var summaryRe = regexp.MustCompile(`(?m)^summary: (\d+) pass, (\d+) fail \((\d+) fixtures\)$`)

type summary struct {
	Pass, Fail, Total int
	Line              string
}

func parseSummary(out string) (summary, bool) {
	m := summaryRe.FindStringSubmatch(out)
	if m == nil {
		return summary{}, false
	}
	p, _ := strconv.Atoi(m[1])
	f, _ := strconv.Atoi(m[2])
	t, _ := strconv.Atoi(m[3])
	return summary{Pass: p, Fail: f, Total: t, Line: m[0]}, true
}

var observedRe = regexp.MustCompile(`^(ACCEPT|REJECT)\s*(?:\[\s*([A-Z_]+)[\]:])?`)

// fixtureResult is one fixture as a verifier reported it.
type fixtureResult struct {
	Status   string // PASS or FAIL
	Observed string // the full observed line
	Verdict  string // ACCEPT, or REJECT and its category
}

// parseResults reads a verifier's per-fixture report, keyed by file name.
func parseResults(out string) map[string]fixtureResult {
	results := map[string]fixtureResult{}
	current := ""
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "PASS  ") || strings.HasPrefix(line, "FAIL  "):
			current = path.Base(strings.TrimSpace(line[6:]))
			results[current] = fixtureResult{Status: line[:4]}
		case current != "" && strings.HasPrefix(strings.TrimSpace(line), "observed: "):
			obs := strings.TrimPrefix(strings.TrimSpace(line), "observed: ")
			r := results[current]
			r.Observed = obs
			if m := observedRe.FindStringSubmatch(obs); m != nil {
				r.Verdict = verdict(m[1], m[2])
			}
			results[current] = r
		}
	}
	return results
}

// ---- step 1: the answer key ------------------------------------------------

type answerKeyData struct {
	Files, Requirements, Accept, Reject int
	Mismatched                          []string
	ManifestLines, ManifestOK           int
}

func hashCommand(e *Env) string {
	if !e.Has("shasum") && e.Has("sha256sum") {
		return cmdManifestSha256sum
	}
	return cmdManifestShasum
}

func stepAnswerKey() Step {
	return Step{
		Number: 1,
		Part:   1,
		Title:  "The answer key",
		Sentence: Text("The tour reads the answer key, conformance.json, which gives every " +
			"fixture its expected verdict, and checks each fixture's bytes against MANIFEST.sha256."),
		Command:  hashCommand,
		Fallback: hashCommand,
		Needs: func(_ context.Context, e *Env) error {
			if err := needBash(e); err != nil {
				return err
			}
			if !e.Has("shasum") && !e.Has("sha256sum") {
				return plainf("neither shasum nor sha256sum is installed")
			}
			return nil
		},
		Run: func(ctx context.Context, e *Env) (*Output, error) {
			fsys := e.FS()
			var key struct {
				Requirements []struct {
					Fixture  string `json:"fixture"`
					Expected string `json:"expected"` // ACCEPT, or REJECT[CATEGORY]
				} `json:"requirements"`
			}
			if err := readJSON(fsys, "conformance.json", &key); err != nil {
				return nil, plainf("conformance.json could not be read")
			}
			names, err := fs.Glob(fsys, "fixtures/*.json")
			if err != nil || len(names) == 0 {
				return nil, plainf("no fixtures/*.json files")
			}
			d := answerKeyData{Files: len(names), Requirements: len(key.Requirements)}
			listed := map[string]bool{}
			for _, r := range key.Requirements {
				listed[r.Fixture] = true
				result, category, _ := strings.Cut(strings.TrimSuffix(r.Expected, "]"), "[")
				switch result {
				case "ACCEPT":
					d.Accept++
				case "REJECT":
					d.Reject++
				}
				f, err := readFixture(fsys, r.Fixture)
				if err != nil || f.Expected.VerifyResult != result || f.Expected.RejectCategory != category {
					d.Mismatched = append(d.Mismatched, r.Fixture)
				}
			}
			for _, n := range names {
				if !listed[n] {
					d.Mismatched = append(d.Mismatched, n)
				}
			}
			manifest, err := fs.ReadFile(fsys, "MANIFEST.sha256")
			if err != nil {
				return nil, plainf("MANIFEST.sha256 could not be read")
			}
			for _, line := range strings.Split(string(manifest), "\n") {
				if strings.TrimSpace(line) != "" {
					d.ManifestLines++
				}
			}
			cmd := exec.CommandContext(ctx, "bash", "-c", cmdManifestShasum)
			if hashCommand(e) == cmdManifestSha256sum {
				cmd = exec.CommandContext(ctx, "bash", "-c", cmdManifestSha256sum)
			}
			out, err := e.run(cmd, "")
			for _, line := range strings.Split(out, "\n") {
				if strings.HasSuffix(line, ": OK") {
					d.ManifestOK++
				}
			}
			if err != nil {
				return &Output{Data: d}, plainf("%d of %d manifest lines match; the rest do not", d.ManifestOK, d.ManifestLines)
			}
			return &Output{Data: d}, nil
		},
		Trim: func(_ *Env, o *Output) ([]string, string, error) {
			d := o.Data.(answerKeyData)
			if len(d.Mismatched) > 0 {
				return nil, "", plainf("conformance.json and the fixtures disagree on %d fixtures", len(d.Mismatched))
			}
			if d.Files != d.Requirements || d.ManifestLines != d.Files || d.ManifestOK != d.ManifestLines {
				return nil, "", plainf("counts differ: %d fixtures, %d requirements, %d of %d manifest lines OK",
					d.Files, d.Requirements, d.ManifestOK, d.ManifestLines)
			}
			lines := []string{
				fmt.Sprintf("%-18s%d files", "fixtures/*.json", d.Files),
				fmt.Sprintf("%-18s%d requirements: %d expect ACCEPT, %d expect REJECT", "conformance.json", d.Requirements, d.Accept, d.Reject),
				fmt.Sprintf("%-18s%s", "", "each one matches the fixture's own expected verdict"),
				fmt.Sprintf("%-18s%d of %d files OK", "MANIFEST.sha256", d.ManifestOK, d.ManifestLines),
			}
			result := fmt.Sprintf("%d fixtures: %d must be accepted, %d must be rejected; %d of %d hashes match.",
				d.Files, d.Accept, d.Reject, d.ManifestOK, d.ManifestLines)
			return lines, result, nil
		},
	}
}

// ---- step 2: two verifiers, two languages ------------------------------------

type twoVerifiersData struct {
	Fixtures       int
	Go, Python     summary
	GoOK, PythonOK bool
	HasPython      bool
	Agree, Compare int
}

func stepTwoVerifiers() Step {
	return Step{
		Number: 2,
		Part:   1,
		Title:  "Two verifiers, two languages",
		Sentence: func(e *Env) string {
			if !pythonInstalled(e) {
				return "Python is not installed on this laptop, so only the Go verifier runs: " +
					"it checks every fixture against the answer key."
			}
			return "The reference verifiers, written separately in Go and in Python, each " +
				"check every fixture against the answer key."
		},
		Command: func(e *Env) string {
			if !pythonInstalled(e) {
				return cmdGoAll
			}
			return cmdGoAll + "\n" + cmdPythonAll
		},
		Fallback: Text(cmdGoAll),
		Needs: func(ctx context.Context, e *Env) error {
			if err := needGo(ctx, e); err != nil {
				return err
			}
			if pythonInstalled(e) {
				return e.pythonReady(ctx)
			}
			return nil
		},
		Run: func(ctx context.Context, e *Env) (*Output, error) {
			names, err := fs.Glob(e.FS(), "fixtures/*.json")
			if err != nil {
				return nil, err
			}
			d := twoVerifiersData{Fixtures: len(names), HasPython: pythonInstalled(e)}
			goOut, err := e.run(exec.CommandContext(ctx, "bash", "-c", cmdGoAll), "")
			if err != nil {
				return nil, plainf("the Go verifier did not finish cleanly")
			}
			d.Go, d.GoOK = parseSummary(goOut)
			if d.HasPython {
				pyOut, err := e.run(exec.CommandContext(ctx, "bash", "-c", cmdPythonAll), "")
				if err != nil {
					return nil, plainf("the Python verifier did not finish cleanly")
				}
				d.Python, d.PythonOK = parseSummary(pyOut)
				goRes, pyRes := parseResults(goOut), parseResults(pyOut)
				for name, g := range goRes {
					d.Compare++
					if p, ok := pyRes[name]; ok && p.Status == g.Status && p.Verdict == g.Verdict {
						d.Agree++
					}
				}
			}
			return &Output{Data: d}, nil
		},
		Trim: func(_ *Env, o *Output) ([]string, string, error) {
			d := o.Data.(twoVerifiersData)
			if !d.GoOK || d.Go.Fail != 0 || d.Go.Total != d.Fixtures {
				return nil, "", plainf("the Go verifier did not report %d of %d", d.Fixtures, d.Fixtures)
			}
			lines := []string{fmt.Sprintf("%-9s%s", "Go", d.Go.Line)}
			if !d.HasPython {
				lines = append(lines, fmt.Sprintf("%-9s%s", "Python", "not installed on this laptop"))
				return lines, fmt.Sprintf("%d/%d on Go. Python is not installed here.", d.Go.Pass, d.Go.Total), nil
			}
			if !d.PythonOK || d.Python.Fail != 0 || d.Python.Total != d.Fixtures {
				return nil, "", plainf("the Python verifier did not report %d of %d", d.Fixtures, d.Fixtures)
			}
			if d.Agree != d.Fixtures || d.Compare != d.Fixtures {
				return nil, "", plainf("the two verifiers differ on %d fixtures", d.Fixtures-d.Agree)
			}
			lines = append(lines,
				fmt.Sprintf("%-9s%s", "Python", d.Python.Line),
				fmt.Sprintf("Same verdict from both on %d of %d fixtures.", d.Agree, d.Fixtures))
			return lines, fmt.Sprintf("%d/%d on Go and %d/%d on Python.", d.Go.Pass, d.Go.Total, d.Python.Pass, d.Python.Total), nil
		},
	}
}

// ---- step 3: watch it refuse ------------------------------------------------

// specPin is the atx-spec commit conformance.json cites, shortened.
func specPin(fsys fs.FS) (string, error) {
	var key struct {
		Spec struct {
			Ref string `json:"ref"`
		} `json:"spec"`
	}
	if err := readJSON(fsys, "conformance.json", &key); err != nil {
		return "", err
	}
	m := regexp.MustCompile(`/blob/([0-9a-f]{7,40})/`).FindStringSubmatch(key.Spec.Ref)
	if m == nil {
		return "", plainf("conformance.json names no spec commit")
	}
	return m[1][:7], nil
}

// ed25519OnlyAccepts counts the v1.1 fixtures that expect ACCEPT and carry
// Ed25519 signatures only.
func ed25519OnlyAccepts(fsys fs.FS) (int, error) {
	names, err := fs.Glob(fsys, "fixtures/*.json")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, name := range names {
		f, err := readFixture(fsys, name)
		if err != nil {
			return 0, err
		}
		var atx struct {
			Version    string `json:"atcVersion"`
			Signatures []struct {
				Algorithm string `json:"algorithm"`
			} `json:"signatures"`
		}
		if json.Unmarshal(f.ATX, &atx) != nil || atx.Version != "1.1" || f.Expected.VerifyResult != "ACCEPT" || len(atx.Signatures) == 0 {
			continue
		}
		only := true
		for _, s := range atx.Signatures {
			if s.Algorithm != "Ed25519" {
				only = false
			}
		}
		if only {
			n++
		}
	}
	return n, nil
}

type refuseRow struct {
	Name     string
	Field    []string // the lines that say which field decides it
	Expected string
	Got      fixtureResult
}

func stepRefuse() Step {
	return Step{
		Number: 3,
		Part:   1,
		Title:  "Watch it refuse",
		Sentence: Text("Fixtures the verifier must refuse: an expired credential, an issuer it " +
			"does not trust, and a forged ML-DSA-65 signature next to a valid Ed25519 one."),
		Limit: func(e *Env) (string, error) {
			pin, err := specPin(e.FS())
			if err != nil {
				return "", err
			}
			n, err := ed25519OnlyAccepts(e.FS())
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("This suite pins the ATX spec at commit %s and still accepts %d v1.1 "+
				"fixtures signed with Ed25519 only, which the newer spec text forbids.", pin, n), nil
		},
		Command:  Text(cmdRefuse),
		Fallback: Text(cmdRefuse),
		Needs: func(ctx context.Context, e *Env) error {
			if err := needGo(ctx, e); err != nil {
				return err
			}
			for _, name := range []string{fixtureExpired, fixtureUntrusted, fixtureForged, fixtureHybrid} {
				if _, err := fs.Stat(e.FS(), name); err != nil {
					return plainf("%s is missing", name)
				}
			}
			return nil
		},
		Run: func(ctx context.Context, e *Env) (*Output, error) {
			fsys := e.FS()
			expired, err1 := readFixture(fsys, fixtureExpired)
			untrusted, err2 := readFixture(fsys, fixtureUntrusted)
			forged, err3 := readFixture(fsys, fixtureForged)
			hybrid, err4 := readFixture(fsys, fixtureHybrid)
			for _, err := range []error{err1, err2, err3, err4} {
				if err != nil {
					return nil, plainf("a step 3 fixture could not be read")
				}
			}
			var expiredATX, untrustedATX struct {
				ExpiresAt string `json:"expiresAt"`
				IssuerDid string `json:"issuerDid"`
			}
			_ = json.Unmarshal(expired.ATX, &expiredATX)
			_ = json.Unmarshal(untrusted.ATX, &untrustedATX)

			forgedLines, err := forgedFieldLines(forged.ATX, hybrid.ATX)
			if err != nil {
				return nil, err
			}
			rows := []refuseRow{
				{Name: path.Base(fixtureExpired), Expected: verdict(expired.Expected.VerifyResult, expired.Expected.RejectCategory),
					Field: []string{fmt.Sprintf("expiresAt %s, verifier clock %s", expiredATX.ExpiresAt, expired.VerifierState.Clock)}},
				{Name: path.Base(fixtureUntrusted), Expected: verdict(untrusted.Expected.VerifyResult, untrusted.Expected.RejectCategory),
					Field: []string{
						"issuerDid " + untrustedATX.IssuerDid,
						"trusted   " + strings.Join(untrusted.VerifierState.TrustedIssuers, ", "),
					}},
				{Name: path.Base(fixtureForged), Expected: verdict(forged.Expected.VerifyResult, forged.Expected.RejectCategory),
					Field: forgedLines},
			}
			out, err := e.run(exec.CommandContext(ctx, "bash", "-c", cmdRefuse), "")
			if err != nil {
				return nil, plainf("the Go verifier did not finish cleanly")
			}
			results := parseResults(out)
			for i := range rows {
				rows[i].Got = results[rows[i].Name]
			}
			return &Output{Data: rows}, nil
		},
		Trim: func(_ *Env, o *Output) ([]string, string, error) {
			rows := o.Data.([]refuseRow)
			var lines, verdicts []string
			for _, r := range rows {
				if r.Got.Status != "PASS" || !strings.HasPrefix(r.Got.Verdict, "REJECT") || r.Got.Verdict != r.Expected {
					return nil, "", plainf("%s was not refused as its answer key says", r.Name)
				}
				lines = append(lines, r.Name)
				for _, f := range r.Field {
					lines = append(lines, "  "+f)
				}
				lines = append(lines, "  "+r.Got.Observed)
				verdicts = append(verdicts, strings.TrimPrefix(r.Got.Verdict, "REJECT "))
			}
			return lines, fmt.Sprintf("%d of %d refused: %s.", len(rows), len(rows), strings.Join(verdicts, ", ")), nil
		},
	}
}

// forgedFieldLines compares the forged credential with the valid hybrid one
// and says which member differs and by how much.
func forgedFieldLines(forged, valid json.RawMessage) ([]string, error) {
	a, err := atxMembers(valid)
	if err != nil {
		return nil, err
	}
	b, err := atxMembers(forged)
	if err != nil {
		return nil, err
	}
	diff := differingMembers(a, b)
	if len(diff) != 1 {
		return nil, plainf("the forged fixture differs from the valid one in %d members, not 1", len(diff))
	}
	var fa, fb struct {
		Signatures []struct {
			Algorithm string `json:"algorithm"`
			Value     string `json:"value"`
		} `json:"signatures"`
	}
	_ = json.Unmarshal(valid, &fa)
	_ = json.Unmarshal(forged, &fb)
	lines := []string{fmt.Sprintf("vs %s: 1 member differs, %s", path.Base(fixtureHybrid), diff[0])}
	for i := range fb.Signatures {
		if i >= len(fa.Signatures) {
			break
		}
		x, errX := base64.StdEncoding.DecodeString(fa.Signatures[i].Value)
		y, errY := base64.StdEncoding.DecodeString(fb.Signatures[i].Value)
		if errX != nil || errY != nil || len(x) != len(y) {
			continue
		}
		changed := 0
		for j := range x {
			changed += bits.OnesCount8(x[j] ^ y[j])
		}
		if changed == 0 {
			lines = append(lines, fmt.Sprintf("%s signature: the same bytes", fb.Signatures[i].Algorithm))
		} else {
			lines = append(lines, fmt.Sprintf("%s signature: %d bit changed of %d bytes", fb.Signatures[i].Algorithm, changed, len(y)))
		}
	}
	return lines, nil
}

// ---- step 4: issue one live ----------------------------------------------

type issueData struct {
	Issuer     string
	Changed    string
	Names      []string
	Expected   map[string]string
	Go, Py     map[string]fixtureResult
	GoSum      summary
	PySum      summary
	GoOK, PyOK bool
}

func stepIssue() Step {
	shown := "DIR=$(mktemp -d); PY=" + venvPython + "\n" + cmdIssue + "\n" + cmdGoDir + "\n" + cmdPythonDir
	return Step{
		Number: 4,
		Part:   1,
		Title:  "Issue one live",
		Sentence: Text("A separate issuer, written from the spec's signing section, makes fresh keys and " +
			"issues a credential; both verifiers judge it as issued, with a signed field " +
			"changed after signing, revoked, and from an issuer they do not trust."),
		Limit: LimitText("These are throwaway keys, made on this laptop and held in memory; " +
			"nothing here was issued by OpenA2A."),
		Command:  Text(shown),
		Fallback: Text(shown),
		Needs: func(ctx context.Context, e *Env) error {
			if err := needGo(ctx, e); err != nil {
				return err
			}
			if !pythonInstalled(e) {
				return plainf("Python is not installed; the issuer is a Python script")
			}
			if _, err := fs.Stat(e.FS(), issuerPath); err != nil {
				return plainf("%s is missing", issuerPath)
			}
			return e.pythonReady(ctx)
		},
		Run: func(ctx context.Context, e *Env) (*Output, error) {
			dir, err := os.MkdirTemp("", "atx-tour-issued-")
			if err != nil {
				return nil, plainf("no temporary directory could be made")
			}
			defer func() { _ = os.RemoveAll(dir) }()
			vars := []string{"DIR=" + dir, "PY=" + venvPython}

			issued, err := e.run(exec.CommandContext(ctx, "bash", "-c", cmdIssue), "", vars...)
			if err != nil {
				return nil, plainf("the issuer did not finish cleanly")
			}
			d := issueData{Expected: map[string]string{}}
			for _, line := range strings.Split(issued, "\n") {
				if rest, ok := strings.CutPrefix(line, "issuer "); ok {
					d.Issuer = strings.TrimSpace(rest)
				}
			}
			fsys := os.DirFS(dir)
			names, err := fs.Glob(fsys, "*.json")
			if err != nil || len(names) == 0 {
				return nil, plainf("the issuer wrote no fixtures")
			}
			sort.Strings(names)
			d.Names = names
			var first, second fixtureFile
			for i, n := range names {
				f, err := readFixture(fsys, n)
				if err != nil {
					return nil, plainf("an issued fixture could not be read")
				}
				d.Expected[n] = verdict(f.Expected.VerifyResult, f.Expected.RejectCategory)
				switch i {
				case 0:
					first = f
				case 1:
					second = f
				}
			}
			if len(names) > 1 {
				a, errA := atxMembers(first.ATX)
				b, errB := atxMembers(second.ATX)
				if errA == nil && errB == nil {
					if diff := differingMembers(a, b); len(diff) == 1 {
						d.Changed = fmt.Sprintf("%s %s -> %s after signing, in %s", diff[0], a[diff[0]], b[diff[0]], names[1])
					}
				}
			}
			goOut, err := e.run(exec.CommandContext(ctx, "bash", "-c", cmdGoDir), "", vars...)
			if err != nil {
				return nil, plainf("the Go verifier did not finish cleanly")
			}
			pyOut, err := e.run(exec.CommandContext(ctx, "bash", "-c", cmdPythonDir), "", vars...)
			if err != nil {
				return nil, plainf("the Python verifier did not finish cleanly")
			}
			d.Go, d.Py = parseResults(goOut), parseResults(pyOut)
			d.GoSum, d.GoOK = parseSummary(goOut)
			d.PySum, d.PyOK = parseSummary(pyOut)
			return &Output{Data: d}, nil
		},
		Trim: func(_ *Env, o *Output) ([]string, string, error) {
			d := o.Data.(issueData)
			n := len(d.Names)
			if !d.GoOK || !d.PyOK || d.GoSum.Pass != n || d.PySum.Pass != n || d.Issuer == "" || d.Changed == "" {
				return nil, "", plainf("the issued credential was not judged as expected")
			}
			lines := []string{
				"issuer   " + d.Issuer,
				"changed  " + d.Changed,
				"",
				fmt.Sprintf("%-25s%-26s%-6s%s", "fixture", "expected", "Go", "Python"),
			}
			for _, name := range d.Names {
				lines = append(lines, fmt.Sprintf("%-25s%-26s%-6s%s",
					strings.TrimSuffix(name, ".json"), d.Expected[name], d.Go[name].Status, d.Py[name].Status))
			}
			return lines, fmt.Sprintf("%d of %d as expected on Go, %d of %d on Python.",
				d.GoSum.Pass, d.GoSum.Total, d.PySum.Pass, d.PySum.Total), nil
		},
	}
}

// ---- step 5: same bytes in every language ------------------------------------

var gateLegRe = regexp.MustCompile(`^\[(go|py|ts)\]\s+(\d+) pass, (\d+) fail \((\d+) vectors\)$`)

type gateData struct {
	Vectors  int
	Legs     map[string]string
	Counts   map[string][2]int // pass, total
	Verifier []string
	Manifest bool
	Gate     string
}

func stepSameBytes() Step {
	return Step{
		Number: 5,
		Part:   1,
		Title:  "Same bytes in every language",
		Sentence: Text("Canonicalizers written separately in Go, Python and TypeScript, and both " +
			"verifiers, must turn every test vector into the same signed bytes."),
		Command:  Text(cmdGate),
		Fallback: Text(cmdGate),
		Needs: func(ctx context.Context, e *Env) error {
			if err := needGo(ctx, e); err != nil {
				return err
			}
			if !e.Has("node") {
				return plainf("Node is not installed, so the TypeScript leg cannot run")
			}
			if !pythonInstalled(e) {
				return plainf("Python is not installed; the gate runs the Python verifier")
			}
			if _, err := fs.Stat(e.FS(), "jcs-vectors/ts/node_modules/canonicalize"); err != nil {
				return plainf("the TypeScript package is not installed (run --setup with the network on)")
			}
			return e.pythonReady(ctx)
		},
		Run: func(ctx context.Context, e *Env) (*Output, error) {
			names, err := fs.Glob(e.FS(), "jcs-vectors/vectors/*.json")
			if err != nil {
				return nil, err
			}
			out, err := e.run(exec.CommandContext(ctx, "bash", "-c", cmdGate), "")
			if err != nil {
				return nil, plainf("the byte-agreement gate did not pass")
			}
			d := gateData{Vectors: len(names), Legs: map[string]string{}, Counts: map[string][2]int{}}
			section, ran := "", ""
			for _, raw := range strings.Split(out, "\n") {
				line := strings.TrimSpace(raw)
				if strings.HasPrefix(line, "=== [") {
					section, _, _ = strings.Cut(strings.TrimPrefix(line, "=== "), " ")
					continue
				}
				if m := gateLegRe.FindStringSubmatch(line); m != nil {
					p, _ := strconv.Atoi(m[2])
					t, _ := strconv.Atoi(m[4])
					d.Legs[m[1]] = line
					d.Counts[m[1]] = [2]int{p, t}
				}
				switch {
				case section == "[verifier/go]" && strings.HasPrefix(raw, "--- PASS: TestJCSVectorsThroughVerifierProjection ("):
					d.Verifier = append(d.Verifier, "[verifier/go] "+line)
				case section == "[verifier/py]" && strings.HasPrefix(line, "Ran "):
					ran = line
				case section == "[verifier/py]" && line == "OK" && ran != "":
					d.Verifier = append(d.Verifier, "[verifier/py] "+ran+": OK")
				case line == "MANIFEST.sha256 OK":
					d.Manifest = true
				case strings.HasPrefix(line, "BYTE-AGREEMENT GATE: "):
					d.Gate = line
				}
			}
			return &Output{Data: d}, nil
		},
		Trim: func(_ *Env, o *Output) ([]string, string, error) {
			d := o.Data.(gateData)
			var lines []string
			for _, leg := range []string{"go", "py", "ts"} {
				c, ok := d.Counts[leg]
				if !ok || c[0] != d.Vectors || c[1] != d.Vectors {
					return nil, "", plainf("the %s leg did not agree on all %d vectors", leg, d.Vectors)
				}
				lines = append(lines, d.Legs[leg])
			}
			if len(d.Verifier) != 2 || !d.Manifest || !strings.HasPrefix(d.Gate, "BYTE-AGREEMENT GATE: PASS") {
				return nil, "", plainf("the gate did not report every leg as passing")
			}
			lines = append(lines, d.Verifier...)
			lines = append(lines, "MANIFEST.sha256 OK", d.Gate)
			return lines, fmt.Sprintf("Go, Python and TypeScript agree on %d of %d vectors, and so do both verifiers.",
				d.Vectors, d.Vectors), nil
		},
	}
}
