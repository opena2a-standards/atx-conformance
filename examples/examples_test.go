// SPDX-License-Identifier: Apache-2.0

// Package examples holds no library code. Its tests run the two wrappers in
// this directory against this repository's own verifiers: wrap-verifier.sh
// around the Go and the Python reference verifier, and serve_verifier.py in
// front of them, reached through the kit's URL adapter with every fixture
// that conformance.json lists.
package examples

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opena2a-standards/atx-conformance/interop"
	"github.com/opena2a-standards/atx-conformance/verifiers/go/verifier"
)

// goVerifierEnv makes this test binary act as the Go reference verifier
// (the same Run that cmd/atx-verify calls), so a wrapper can run it as a
// command without a separate build.
const goVerifierEnv = "ATX_EXAMPLES_ACT_AS_GO_VERIFIER"

func TestMain(m *testing.M) {
	if os.Getenv(goVerifierEnv) == "1" {
		os.Exit(verifier.Run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// repoRoot is the repository root; go test runs in this directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// row is one fixture and the verdict conformance.json expects for it.
type row struct {
	fixture  interop.Fixture
	want     interop.Verdict
	expected string // as conformance.json writes it, for example REJECT[EXPIRED]
}

// answerKey reads every requirement of conformance.json and the credential
// (the "atx" member, its bytes as the file holds them) of the fixture each
// names, and checks that the key covers every file in fixtures/. Every read
// goes through os.DirFS, so it stays inside the repository.
func answerKey(t *testing.T) []row {
	t.Helper()
	root := repoRoot(t)
	repo := os.DirFS(root)
	data, err := fs.ReadFile(repo, "conformance.json")
	if err != nil {
		t.Fatal(err)
	}
	var key struct {
		Requirements []struct {
			Fixture  string `json:"fixture"`
			Expected string `json:"expected"`
		} `json:"requirements"`
	}
	if err := json.Unmarshal(data, &key); err != nil {
		t.Fatalf("conformance.json: %v", err)
	}
	var rows []row
	for _, req := range key.Requirements {
		path := filepath.Join(root, filepath.FromSlash(req.Fixture))
		raw, err := fs.ReadFile(repo, req.Fixture)
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Credential json.RawMessage `json:"atx"`
		}
		if err := json.Unmarshal(raw, &f); err != nil || len(f.Credential) == 0 {
			t.Fatalf("%s: no credential (atx member) read: %v", req.Fixture, err)
		}
		want := interop.Accept
		switch {
		case req.Expected == "ACCEPT":
		case strings.HasPrefix(req.Expected, "REJECT"):
			want = interop.Reject
		default:
			t.Fatalf("%s: expected %q is neither ACCEPT nor REJECT", req.Fixture, req.Expected)
		}
		rows = append(rows, row{
			fixture:  interop.Fixture{Name: filepath.Base(path), Path: path, Credential: f.Credential},
			want:     want,
			expected: req.Expected,
		})
	}
	files, err := fs.Glob(repo, "fixtures/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 || len(rows) != len(files) {
		t.Fatalf("conformance.json lists %d fixtures and fixtures/ holds %d files; want the same, nonzero", len(rows), len(files))
	}
	return rows
}

// compare sends every row to verify and fails unless each verdict agrees
// with conformance.json. It logs one line per fixture and the total.
func compare(t *testing.T, rows []row, verify func(interop.Fixture) interop.Result) {
	t.Helper()
	agree := 0
	for _, r := range rows {
		got := verify(r.fixture)
		mark := "agree"
		if got.Verdict == r.want {
			agree++
		} else {
			mark = "DISAGREE"
			t.Errorf("%s: got %s, conformance.json expects %s; raw %q", r.fixture.Name, got.Verdict, r.expected, got.Raw)
		}
		said := got.Reason
		if said == "" {
			said = got.Raw
		}
		t.Logf("%-8s %-56s expected %-27s got %-14s %s", mark, r.fixture.Name, r.expected, got.Verdict, firstLine(said))
	}
	t.Logf("%d of %d fixtures agree with conformance.json", agree, len(rows))
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func needSh(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("skipped: no sh on PATH; the shell wrapper needs a POSIX shell")
	}
}

// python is the interpreter the tests use: $ATX_PYTHON, or python3 on PATH.
func python(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("ATX_PYTHON"); p != "" {
		return p
	}
	p, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("skipped: python3 is not on PATH and ATX_PYTHON is not set; the HTTP wrapper and the Python verifier need Python 3")
	}
	return p
}

// pythonWithVerifierPackages is python, once it imports the Python reference
// verifier's packages.
func pythonWithVerifierPackages(t *testing.T) string {
	t.Helper()
	py := python(t)
	if out, err := exec.Command(py, "-c", "import cryptography, dilithium_py").CombinedOutput(); err != nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		t.Skipf("skipped: %s cannot import the Python reference verifier's packages (%s); install them with `%s -m pip install -r verifiers/python/requirements.txt`, or set ATX_PYTHON to an interpreter that has them", py, lines[len(lines)-1], py)
	}
	return py
}

func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// runShellWrapper runs wrap-verifier.sh with args and applies the command
// contract to what it did: exit 0 ACCEPT, exit 1 REJECT, anything else
// COULD_NOT_READ, and JSON on stdout wins.
func runShellWrapper(t *testing.T, env []string, stdin []byte, args ...string) (interop.Result, int) {
	t.Helper()
	root := repoRoot(t)
	cmd := exec.Command("sh", append([]string{filepath.Join(root, "examples", "wrap-verifier.sh")}, args...)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), env...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.Output()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("running the shell wrapper: %v", err)
		}
		code = exit.ExitCode()
	}
	fallback := interop.Unreadable
	switch code {
	case 0:
		fallback = interop.Accept
	case 1:
		fallback = interop.Reject
	}
	return interop.Classify(fallback, out), code
}

// startHTTPWrapper starts serve_verifier.py on 127.0.0.1 at a port the system
// picks and returns the URL it prints; the wrapper stops when the test ends.
func startHTTPWrapper(t *testing.T, py string, env []string, args ...string) string {
	t.Helper()
	root := repoRoot(t)
	cmd := exec.Command(py, append([]string{filepath.Join(root, "examples", "serve_verifier.py"), "0"}, args...)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("HTTP wrapper stderr:\n%s", stderr.String())
		}
	})
	first := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		first <- strings.TrimSpace(line)
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case line := <-first:
		url := strings.TrimPrefix(line, "listening on ")
		if !strings.HasPrefix(url, "http://127.0.0.1:") {
			t.Fatalf("HTTP wrapper printed %q, want \"listening on http://127.0.0.1:<port>/\"", line)
		}
		return url
	case <-time.After(30 * time.Second):
		t.Fatal("HTTP wrapper did not print its URL within 30s")
	}
	return ""
}

// TestShellWrapperAroundTheGoVerifier runs wrap-verifier.sh around the Go
// reference verifier on every fixture.
func TestShellWrapperAroundTheGoVerifier(t *testing.T) {
	needSh(t)
	verifierCmd := self(t)
	compare(t, answerKey(t), func(f interop.Fixture) interop.Result {
		r, _ := runShellWrapper(t, []string{goVerifierEnv + "=1"}, nil, f.Path, verifierCmd)
		return r
	})
}

// TestShellWrapperAroundThePythonVerifier runs wrap-verifier.sh around the
// Python reference verifier on every fixture.
func TestShellWrapperAroundThePythonVerifier(t *testing.T) {
	needSh(t)
	py := pythonWithVerifierPackages(t)
	verifyPy := filepath.Join(repoRoot(t), "verifiers", "python", "verify.py")
	compare(t, answerKey(t), func(f interop.Fixture) interop.Result {
		r, _ := runShellWrapper(t, nil, nil, f.Path, py, verifyPy)
		return r
	})
}

// fakeVerifier is a command that prints $FAKE_OUTPUT and ignores its file.
var fakeVerifier = []string{"sh", "-c", `printf '%s\n' "$FAKE_OUTPUT"`, "fake-verifier"}

// TestShellWrapperReadsTheVerifiersWords checks the line the shell wrapper
// decides on. This repository's verifiers print the expected verdict before
// the observed one, so the defaults must read the observed line only; a
// verifier's own words are set with ACCEPT_TEXT and REJECT_TEXT, and the
// reject text is checked first because "invalid" contains "valid".
func TestShellWrapperReadsTheVerifiersWords(t *testing.T) {
	needSh(t)
	cases := []struct {
		name       string
		env        []string
		output     string
		wantCode   int
		want       interop.Verdict
		wantReason string
	}{
		{"observed REJECT after expected ACCEPT", nil,
			"FAIL  x.json\n       expected: ACCEPT\n       observed: REJECT[SIGNATURE_INVALID: bad]",
			1, interop.Reject, "observed: REJECT[SIGNATURE_INVALID: bad]"},
		{"observed ACCEPT after expected REJECT", nil,
			"FAIL  x.json\n       expected: REJECT [EXPIRED]\n       observed: ACCEPT",
			0, interop.Accept, "observed: ACCEPT"},
		{"no verdict line is couldn't read", nil,
			"missing dependency: dilithium-py", 2, interop.Unreadable, ""},
		{"quotes and backslashes stay valid JSON", nil,
			`observed: REJECT[PARSE_ERROR: "x" at \u0001]`, 1, interop.Reject, `observed: REJECT[PARSE_ERROR: "x" at \u0001]`},
		{"own words, invalid", []string{"ACCEPT_TEXT=valid", "REJECT_TEXT=invalid"},
			"credential invalid: expired", 1, interop.Reject, "credential invalid: expired"},
		{"own words, valid", []string{"ACCEPT_TEXT=valid", "REJECT_TEXT=invalid"},
			"credential valid", 0, interop.Accept, "credential valid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := append([]string{"FAKE_OUTPUT=" + c.output}, c.env...)
			got, code := runShellWrapper(t, env, nil, append([]string{"some-fixture.json"}, fakeVerifier...)...)
			if code != c.wantCode || got.Verdict != c.want || got.Reason != c.wantReason {
				t.Errorf("exit %d %+v, want exit %d verdict %s reason %q", code, got, c.wantCode, c.want, c.wantReason)
			}
			if c.want == interop.Unreadable && !strings.Contains(got.Raw, c.output) {
				t.Errorf("raw %q does not pass the verifier's output through", got.Raw)
			}
		})
	}
}

// TestShellWrapperPassesStdin hands the credential on stdin to a verifier
// that reads it there, when the file argument is "-".
func TestShellWrapperPassesStdin(t *testing.T) {
	needSh(t)
	reader := []string{"sh", "-c", `if grep -q '"revoked": true'; then echo "observed: REJECT[REVOKED]"; else echo "observed: ACCEPT"; fi`}
	for stdin, want := range map[string]interop.Verdict{`{"revoked": true}`: interop.Reject, `{"revoked": false}`: interop.Accept} {
		got, _ := runShellWrapper(t, nil, []byte(stdin), append([]string{"-"}, reader...)...)
		if got.Verdict != want {
			t.Errorf("stdin %s: got %+v, want %s", stdin, got, want)
		}
	}
}

// TestHTTPWrapperInFrontOfTheGoVerifier sends every fixture through the URL
// adapter to serve_verifier.py, which runs the Go reference verifier through
// wrap-verifier.sh on the fixture its ATX-Fixture header names.
func TestHTTPWrapperInFrontOfTheGoVerifier(t *testing.T) {
	needSh(t)
	py := python(t)
	url := startHTTPWrapper(t, py, []string{goVerifierEnv + "=1"},
		"--fixtures", "fixtures", "sh", "examples/wrap-verifier.sh", "{file}", self(t))
	adapter := interop.NewURLAdapter(url, time.Minute)
	compare(t, answerKey(t), func(f interop.Fixture) interop.Result {
		return adapter.Verify(context.Background(), f)
	})
}

// TestSelfTest2PythonVerifierBehindTheHTTPWrapper is self-test 2 at the
// adapter level: the Python reference verifier behind serve_verifier.py,
// every fixture of conformance.json sent through the URL adapter, every
// verdict compared with conformance.json.
func TestSelfTest2PythonVerifierBehindTheHTTPWrapper(t *testing.T) {
	needSh(t)
	py := pythonWithVerifierPackages(t)
	url := startHTTPWrapper(t, py, nil,
		"--fixtures", "fixtures", "sh", "examples/wrap-verifier.sh", "{file}", py, "verifiers/python/verify.py")
	t.Logf("HTTP wrapper at %s, Python %s", url, py)
	adapter := interop.NewURLAdapter(url, time.Minute)
	compare(t, answerKey(t), func(f interop.Fixture) interop.Result {
		return adapter.Verify(context.Background(), f)
	})
}

// TestHTTPWrapperHandsTheCommandThePostedCredential checks the wrapper with
// no fixture directory: {file} is a file holding the posted bytes, no {file}
// means stdin, and the exit status becomes 200, 422 or 500.
func TestHTTPWrapperHandsTheCommandThePostedCredential(t *testing.T) {
	needSh(t)
	py := python(t)
	rows := answerKey(t)
	cred := rows[0].fixture
	prefix := []rune(string(cred.Credential))[:200]
	cases := []struct {
		name    string
		command []string
		want    interop.Verdict
		wantRaw string
	}{
		{"{file} holds the posted bytes, exit 0 is ACCEPT", []string{"cat", "{file}"}, interop.Accept, string(prefix)},
		{"no {file} means stdin, exit 1 is REJECT", []string{"sh", "-c", "cat; exit 1"}, interop.Reject, string(prefix)},
		{"exit 3 is couldn't read", []string{"sh", "-c", "echo broken; exit 3", "sh", "{file}"}, interop.Unreadable, "broken\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			url := startHTTPWrapper(t, py, nil, c.command...)
			got := interop.NewURLAdapter(url, 30*time.Second).Verify(context.Background(), cred)
			if got.Verdict != c.want || got.Raw != c.wantRaw {
				t.Errorf("got verdict %s raw %q, want %s raw %q", got.Verdict, got.Raw, c.want, c.wantRaw)
			}
		})
	}
}

// TestHTTPWrapperChecksTheNamedFixture refuses, as couldn't read and without
// running the command, a request whose credential is not the credential of
// the fixture its ATX-Fixture header names.
func TestHTTPWrapperChecksTheNamedFixture(t *testing.T) {
	needSh(t)
	py := python(t)
	url := startHTTPWrapper(t, py, nil, "--fixtures", "fixtures", "sh", "-c", "echo the command ran; exit 0")
	adapter := interop.NewURLAdapter(url, 30*time.Second)
	byName := map[string]interop.Fixture{}
	for _, r := range answerKey(t) {
		byName[r.fixture.Name] = r.fixture
	}
	baseline := byName["baseline-valid.json"]
	for _, name := range []string{"expired.json", "", "../conformance.json", "no-such-fixture.json"} {
		f := baseline
		f.Name = name
		got := adapter.Verify(context.Background(), f)
		if got.Verdict != interop.Unreadable || !strings.Contains(got.Reason, "is not the credential of the fixture") {
			t.Errorf("name %q: got %+v, want couldn't read with the wrapper's reason", name, got)
		}
	}
	// The same credential under each fixture name that carries it is accepted
	// by the gate and reaches the command.
	for _, name := range []string{"baseline-valid.json", "revoked-crl-only.json", "threshold-1of3-cosignature.json"} {
		f := baseline
		f.Name = name
		if got := adapter.Verify(context.Background(), f); got.Verdict != interop.Accept || !strings.Contains(got.Raw, "the command ran") {
			t.Errorf("name %q: got %+v, want the command to run and answer ACCEPT", name, got)
		}
	}
}

// TestHTTPWrapperUsage exits 2 with its usage line when started wrongly.
func TestHTTPWrapperUsage(t *testing.T) {
	py := python(t)
	script := filepath.Join(repoRoot(t), "examples", "serve_verifier.py")
	for _, args := range [][]string{{}, {"8080"}, {"port", "cat", "{file}"}, {"0", "--fixtures"}, {"0", "--fixtures", "fixtures"}} {
		out, err := exec.Command(py, append([]string{script}, args...)...).CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(out), "usage: serve_verifier.py") {
			t.Errorf("args %q: err %v output %q, want exit 2 with the usage line", args, err, out)
		}
	}
}
