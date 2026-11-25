// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// dummies holds the testdata verifiers TestMain builds: goverifier,
// acceptall and jwtonly, each a path to an executable.
var dummies = map[string]string{}

// helperArg is the first argument that makes the test binary act as a
// verifier for the adapter tests (see helperMain), so they need no shell
// and run the same on every system.
const helperArg = "interop-helper"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == helperArg {
		os.Exit(helperMain(os.Args[2:]))
	}
	dir, err := os.MkdirTemp("", "atx-interop-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	code := func() int {
		defer os.RemoveAll(dir)
		for _, name := range []string{"goverifier", "acceptall", "jwtonly"} {
			out := filepath.Join(dir, name)
			if runtime.GOOS == "windows" {
				out += ".exe"
			}
			build := exec.Command("go", "build", "-o", out, "./testdata/"+name)
			if b, err := build.CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "building testdata/%s: %v\n%s", name, err, b)
				return 2
			}
			dummies[name] = out
		}
		return m.Run()
	}()
	os.Exit(code)
}

// helperMain is the test binary acting as a verifier. args[0] is the role:
//
//	exit N [text]  print text on stdout and exit N
//	stderr N text  print text on stderr and exit N
//	stdin N        copy stdin to stdout and exit N
//	args           print the remaining arguments, one per line, and exit 0
//	sleep          sleep for a minute
func helperMain(args []string) int {
	if len(args) == 0 {
		return 99
	}
	code := 0
	if len(args) > 1 {
		code, _ = strconv.Atoi(args[1])
	}
	switch args[0] {
	case "exit":
		if len(args) > 2 {
			fmt.Print(args[2])
		}
		return code
	case "stderr":
		fmt.Fprint(os.Stderr, args[2])
		return code
	case "stdin":
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return 98
		}
		if _, err := os.Stdout.Write(b); err != nil {
			return 98
		}
		return code
	case "args":
		for _, a := range args[1:] {
			fmt.Println(a)
		}
		return 0
	case "sleep":
		time.Sleep(time.Minute)
		return 0
	}
	return 99
}

// quote is p as one word of a --verifier command: in double quotes, with
// each backslash and double quote escaped.
func quote(p string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p) + `"`
}

// helperCommand is a --verifier command that runs the test binary as a
// helper with the given role words.
func helperCommand(words ...string) string {
	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}
	cmd := quote(self) + " " + helperArg
	for _, w := range words {
		cmd += " " + quote(w)
	}
	return cmd
}
