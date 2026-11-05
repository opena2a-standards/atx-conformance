// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fakeMatrix is a directory with a small matrix.json, never the real file.
func fakeMatrix(t *testing.T, pinned bool) string {
	t.Helper()
	dir := t.TempDir()
	text := `{"version":"1.2","updated":"2026-11-01","techniques":[{"id":"T-3001","name":"A name","tactic":"a-tactic","evidenceTier":"observed"}]}`
	if err := os.WriteFile(filepath.Join(dir, "matrix.json"), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	if pinned {
		sum := sha256.Sum256([]byte(text))
		old := matrixSHA256
		matrixSHA256 = hex.EncodeToString(sum[:])
		t.Cleanup(func() { matrixSHA256 = old })
	}
	return dir
}

func TestStep8HiddenWithAReasonForEachFailedCondition(t *testing.T) {
	for _, c := range []struct {
		name   string
		matrix func(t *testing.T) string
		noJq   bool
		reason string
	}{
		{"no --matrix", func(*testing.T) string { return "" }, false, `^no --matrix path was given$`},
		{"no matrix.json", func(t *testing.T) string { return t.TempDir() }, false, `^the --matrix directory has no matrix\.json$`},
		{"another file", func(t *testing.T) string { return fakeMatrix(t, false) }, false,
			`^the --matrix checkout's matrix\.json is not the one this step was measured with: run git -C \S+ checkout 8e2a798f1c44$`},
		{"no jq", func(t *testing.T) string { return fakeMatrix(t, true) }, true, `^jq is not installed$`},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, _ := testEnv(t)
			e.Timeout = 10 * time.Second
			e.Matrix = c.matrix(t)
			if c.noJq {
				e.LookPath = func(p string) (string, error) {
					if p == "jq" {
						return "", exec.ErrNotFound
					}
					return exec.LookPath(p)
				}
			}
			var pre bytes.Buffer
			st := Preflight(context.Background(), e, Optional(), NewScreen(&pre, false))
			if s := st.Steps[0]; s.Status != Hidden || !regexp.MustCompile(c.reason).MatchString(s.Reason) {
				t.Fatalf("step 8 is %q with reason %q, want hidden with %s", s.Status, s.Reason, c.reason)
			}
		})
	}
}

func TestStep8ShowsTheMeasuredLinesAndRefusesAnythingElse(t *testing.T) {
	trim := stepTechnique().Trim
	measured := "Threat matrix version 1.2, updated 2026-11-01: 61 techniques\n" +
		"T-3001 System Prompt Credential Extraction (credential-harvest): evidence tier observed\n"
	lines, result, err := trim(nil, &Output{Data: measured})
	if err != nil || strings.Join(lines, "\n")+"\n" != measured || result == "" {
		t.Fatalf("lines %q, err %v", lines, err)
	}
	for _, other := range []string{
		"",
		"Threat matrix version 1.2, updated 2026-11-01: 61 techniques\n",
		strings.Replace(measured, "61 techniques", "64 techniques", 1),
		strings.Replace(measured, "tier observed", "tier validated", 1),
	} {
		if _, _, err := trim(nil, &Output{Data: other}); err == nil {
			t.Errorf("step 8 passed on %q", other)
		}
	}
}

func TestStep8RunsJqOnAFileOnDisk(t *testing.T) {
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	e, _ := testEnv(t)
	e.Timeout = 10 * time.Second
	e.Matrix = fakeMatrix(t, true)
	out := RunStep(context.Background(), e, stepTechnique())
	// The fake file is not the measured one, so its lines are refused; what
	// this proves is that jq ran on it under the tour's sandbox and printed.
	if out.Err == nil || Reason(out.Err, e.Timeout) != "matrix.json did not give the lines this step was measured with" {
		t.Fatalf("step 8 on the fake file: %v", out.Err)
	}
	limit, err := matrixLimit(e)
	if err != nil || limit != "This file holds 1 techniques, version 1.2." {
		t.Fatalf("limit %q, err %v", limit, err)
	}
}
