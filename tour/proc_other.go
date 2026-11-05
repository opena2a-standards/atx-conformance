// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package tour

import (
	"os"
	"os/exec"
)

// setProcessGroup leaves cmd as it is: outside Unix a timeout stops the
// command itself.
func setProcessGroup(cmd *exec.Cmd) {}

// isTerminal reports whether f is a terminal.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// cbreak is not available outside Unix: keys are read a line at a time.
func cbreak(stdin *os.File) (restore func(), ok bool) { return func() {}, false }
