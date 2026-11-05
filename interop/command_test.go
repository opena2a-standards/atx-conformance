// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSplitCommand(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"verify {file}", []string{"verify", "{file}"}},
		{"  python3   my_verifier.py\t--strict  ", []string{"python3", "my_verifier.py", "--strict"}},
		{`'my verifier' "--name=a b" {file}`, []string{"my verifier", "--name=a b", "{file}"}},
		{`a"b c"d`, []string{"ab cd"}},
		{`C:\tools\verify.exe {file}`, []string{`C:\tools\verify.exe`, "{file}"}},
		{`"C:\Program Files\v\verify.exe" {file}`, []string{`C:\Program Files\v\verify.exe`, "{file}"}},
		{`"say \"hi\" \\ \n"`, []string{`say "hi" \ \n`}},
		{`'$HOME ~ | > ;'`, []string{`$HOME ~ | > ;`}},
		{`x '' y`, []string{"x", "", "y"}},
	}
	for _, c := range cases {
		got, err := splitCommand(c.in)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitCommand(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "   ", `verify 'open`, `verify "open`, `verify "open\"`} {
		if got, err := splitCommand(bad); err == nil {
			t.Errorf("splitCommand(%q) = %q, want an error", bad, got)
		}
	}
}

// verifyWith runs one fixture through a command adapter.
func verifyWith(t *testing.T, command string, timeout time.Duration, f Fixture) Result {
	t.Helper()
	return NewCommandAdapter(command, timeout).Verify(context.Background(), f)
}

func TestCommandAdapterExitCodes(t *testing.T) {
	f := Fixture{Name: "x.json", Credential: []byte(`{"id":"x"}`)}
	cases := []struct {
		name    string
		command string
		want    Verdict
		raw     string
	}{
		{"exit 0 is ACCEPT", helperCommand("exit", "0"), Accept, ""},
		{"exit 1 is REJECT", helperCommand("exit", "1", "bad signature"), Reject, "bad signature"},
		{"exit 3 is couldn't read", helperCommand("exit", "3", "boom"), Unreadable, "exit status 3: boom"},
		{"stderr is kept when stdout is blank", helperCommand("stderr", "1", "on stderr"), Reject, "on stderr"},
		{"JSON REJECT wins over exit 0", helperCommand("exit", "0", `{"verdict":"REJECT","reason":"expired"}`), Reject, `{"verdict":"REJECT","reason":"expired"}`},
		{"JSON valid true wins over exit 2", helperCommand("exit", "2", `{"valid": true}`), Accept, `{"valid": true}`},
		{"JSON ERROR is couldn't read", helperCommand("exit", "0", `{"verdict":"ERROR"}`), Unreadable, `{"verdict":"ERROR"}`},
		{"JSON valid false with an object reason wins over exit 0", helperCommand("exit", "0", `{"valid":false,"reason":{"code":"expired"}}`), Reject, `{"valid":false,"reason":{"code":"expired"}}`},
		{"JSON REJECT with a number reason wins over exit 0", helperCommand("exit", "0", `{"verdict":"REJECT","reason":42}`), Reject, `{"verdict":"REJECT","reason":42}`},
		{"JSON REJECT with a list reason wins over exit 0", helperCommand("exit", "0", `{"verdict":"REJECT","reason":["expired"]}`), Reject, `{"verdict":"REJECT","reason":["expired"]}`},
		{"JSON ERROR with an object reason at exit 0 is couldn't read", helperCommand("exit", "0", `{"verdict":"ERROR","reason":{"e":1}}`), Unreadable, `{"verdict":"ERROR","reason":{"e":1}}`},
		{"JSON verdict of another type leaves valid to decide", helperCommand("exit", "0", `{"verdict":42,"valid":false}`), Reject, `{"verdict":42,"valid":false}`},
		{"JSON verdict with another word leaves valid false to decide over exit 0", helperCommand("exit", "0", `{"verdict":"INVALID","valid":false}`), Reject, `{"verdict":"INVALID","valid":false}`},
		{"JSON verdict with another word and a reason leaves valid false to decide over exit 0", helperCommand("exit", "0", `{"verdict":"INVALID","valid":false,"reason":"expired"}`), Reject, `{"verdict":"INVALID","valid":false,"reason":"expired"}`},
		{"JSON verdict with another word leaves valid true to decide over exit 1", helperCommand("exit", "1", `{"verdict":"rejected","valid":true}`), Accept, `{"verdict":"rejected","valid":true}`},
		{"JSON verdict with another word and no valid leaves exit 1 to decide", helperCommand("exit", "1", `{"verdict":"MAYBE"}`), Reject, `{"verdict":"MAYBE"}`},
		{"JSON verdict with another word and no valid leaves exit 0 to decide", helperCommand("exit", "0", `{"verdict":"MAYBE"}`), Accept, `{"verdict":"MAYBE"}`},
		{"JSON valid text leaves exit 0 to decide", helperCommand("exit", "0", `{"valid":"false"}`), Accept, `{"valid":"false"}`},
		{"JSON valid text leaves exit 1 to decide", helperCommand("exit", "1", `{"valid":"true"}`), Reject, `{"valid":"true"}`},
		{"JSON valid number leaves exit 3 to decide", helperCommand("exit", "3", `{"valid":1}`), Unreadable, `exit status 3: {"valid":1}`},
		{"a log line before the JSON leaves exit 0 to decide", helperCommand("exit", "0", "loaded 3 keys\n"+`{"verdict":"REJECT"}`), Accept, "loaded 3 keys\n" + `{"verdict":"REJECT"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := verifyWith(t, c.command, 30*time.Second, f)
			if got.Verdict != c.want || got.Raw != c.raw {
				t.Errorf("got %+v; want verdict %s, raw %q", got, c.want, c.raw)
			}
		})
	}
	if got := verifyWith(t, helperCommand("exit", "1", `{"verdict":"REJECT","reason":"expired"}`), 30*time.Second, f); got.Reason != "expired" {
		t.Errorf("reason = %q, want expired", got.Reason)
	}
}

func TestCommandAdapterRawIsFirst200Characters(t *testing.T) {
	long := strings.Repeat("é", 300)
	got := verifyWith(t, helperCommand("exit", "1", long), 30*time.Second, Fixture{})
	if got.Raw != strings.Repeat("é", 200) {
		t.Errorf("raw holds %d characters, want the first 200", len([]rune(got.Raw)))
	}
}

func TestCommandAdapterTimeoutAndStartFailure(t *testing.T) {
	start := time.Now()
	got := verifyWith(t, helperCommand("sleep"), 500*time.Millisecond, Fixture{})
	if got.Verdict != Unreadable || !strings.HasPrefix(got.Raw, "no answer within 500ms") {
		t.Errorf("timeout: got %+v", got)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("timeout took %s", d)
	}
	got = verifyWith(t, quote(filepath.Join(t.TempDir(), "no-such-verifier")), 30*time.Second, Fixture{})
	if got.Verdict != Unreadable || !strings.HasPrefix(got.Raw, "could not start: ") {
		t.Errorf("missing command: got %+v", got)
	}
	got = verifyWith(t, `verify "open`, 30*time.Second, Fixture{})
	if got.Verdict != Unreadable || !strings.Contains(got.Raw, "not closed") {
		t.Errorf("unsplittable command: got %+v", got)
	}
}

func TestCommandAdapterStdinAndFile(t *testing.T) {
	cred := []byte(`{"id":"urn:example:credential","version":"1.1"}`)
	got := verifyWith(t, helperCommand("stdin", "1"), 30*time.Second, Fixture{Credential: cred})
	if got.Verdict != Reject || got.Raw != string(cred) {
		t.Errorf("with no {file} stdin should carry the credential: got %+v", got)
	}

	dir := filepath.Join(t.TempDir(), "a dir with spaces")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "x.json")
	got = verifyWith(t, helperCommand("args", "--in={file}", "{file}"), 30*time.Second, Fixture{Path: path, Credential: cred})
	want := "--in=" + path + "\n" + path + "\n"
	if got.Verdict != Accept || got.Raw != firstChars(want, rawLimit) {
		t.Errorf("{file} should become the fixture path inside one word: got %+v, want raw %q", got, want)
	}
	got = verifyWith(t, helperCommand("stdin", "0"), 30*time.Second, Fixture{Path: path, Credential: cred})
	if got.Raw != string(cred) {
		t.Errorf("a command with no {file} reads the credential: got %+v", got)
	}
	got = verifyWith(t, helperCommand("stdin", "0", "{file}"), 30*time.Second, Fixture{Path: path, Credential: cred})
	if got.Raw != "" {
		t.Errorf("a command with {file} gets an empty stdin: got %+v", got)
	}
}
