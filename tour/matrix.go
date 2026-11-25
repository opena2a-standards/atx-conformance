// SPDX-License-Identifier: Apache-2.0

package tour

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Optional is step 8, which needs a checkout of the agent threat matrix given
// with --matrix. Without it the step is hidden.
func Optional() []Step {
	return []Step{stepTechnique()}
}

// The threat matrix file step 8 was measured with: matrix.json at commit
// 8e2a798f1c44 of the agent threat matrix.
var (
	matrixSHA256 = "6487f04925637f92ad424d6daabc6dd5eb8c9ad2d893678aba0c56f0894268b1"
	matrixCommit = "8e2a798f1c44"
)

const (
	matrixFile = "matrix.json"
	// cmdTechnique runs as `bash -c` in the matrix checkout, under the macOS
	// sandbox profile that refuses every outbound connection.
	cmdTechnique = `jq -r '"Threat matrix version \(.version), updated \(.updated): \(.techniques|length) techniques", ` +
		`(.techniques[] | select(.id=="T-3001") | "\(.id) \(.name) (\(.tactic)): evidence tier \(.evidenceTier)")' matrix.json`
	// cmdTechniqueByHand needs no jq: T-3001 is techniques[15] in that file.
	cmdTechniqueByHand = `for k in id name tactic evidenceTier; do plutil -extract techniques.15.$k raw -o - matrix.json; done`
)

var errNoMatrix = plainf("no --matrix path was given")

// needMatrix is a --matrix checkout whose matrix.json is the measured one, and
// bash and jq to read it.
func needMatrix(_ context.Context, e *Env) error {
	if e.Matrix == "" {
		return errNoMatrix
	}
	b, err := fs.ReadFile(os.DirFS(e.Matrix), matrixFile)
	if err != nil {
		return plainf("the --matrix directory has no %s", matrixFile)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != matrixSHA256 {
		return plainf("the --matrix checkout's %s is not the one this step was measured with: run git -C %s checkout %s",
			matrixFile, shellQuote(e.Matrix), matrixCommit)
	}
	if err := needBash(e); err != nil {
		return err
	}
	if !e.Has("jq") {
		return plainf("jq is not installed")
	}
	return nil
}

// matrixLimit is said before step 8: how many techniques the file holds, and
// its version, read from the file.
func matrixLimit(e *Env) (string, error) {
	b, err := fs.ReadFile(os.DirFS(e.Matrix), matrixFile)
	if err != nil {
		return "", err
	}
	var m struct {
		Version    string            `json:"version"`
		Techniques []json.RawMessage `json:"techniques"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return "", err
	}
	if m.Version == "" || len(m.Techniques) == 0 {
		return "", fmt.Errorf("no version or no techniques in %s", matrixFile)
	}
	return fmt.Sprintf("This file holds %d techniques, version %s.", len(m.Techniques), m.Version), nil
}

func stepTechnique() Step {
	return Step{
		Number: 8,
		Part:   3,
		Title:  "Optional: one threat technique",
		Sentence: Text("The tour reads one technique from the threat matrix file on disk, with the " +
			"network blocked, and prints it with its evidence tier."),
		Limit:   matrixLimit,
		Command: Text(cmdTechnique),
		Fallback: func(e *Env) string {
			dir := "<agent-threat-matrix checkout>"
			if e.Matrix != "" {
				dir = shellQuote(e.Matrix)
			}
			return "cd " + dir + " && " + cmdTechniqueByHand
		},
		Needs: needMatrix,
		Run: func(ctx context.Context, e *Env) (*Output, error) {
			out, err := e.runIn(exec.CommandContext(ctx, "bash", "-c", cmdTechnique),
				filepath.Clean(e.Matrix), "the threat matrix checkout", sandboxProfile)
			if err != nil {
				return nil, plainf("jq did not read %s", matrixFile)
			}
			return &Output{Data: out}, nil
		},
		Trim: func(_ *Env, o *Output) ([]string, string, error) {
			lines := strings.Split(strings.TrimSpace(o.Data.(string)), "\n")
			if len(lines) != 2 || !strings.HasPrefix(lines[0], "Threat matrix version 1.2, ") ||
				!strings.HasSuffix(lines[0], ": 61 techniques") ||
				!strings.HasPrefix(lines[1], "T-3001 ") || !strings.HasSuffix(lines[1], ": evidence tier observed") {
				return nil, "", plainf("%s did not give the lines this step was measured with", matrixFile)
			}
			return lines, "T-3001 is in the observed tier, read from the file on disk.", nil
		},
	}
}
