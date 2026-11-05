// SPDX-License-Identifier: Apache-2.0

//go:build unix

package tour

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// setProcessGroup starts cmd in a process group of its own, so a timeout
// stops the command and everything it started (go run starts the verifier
// it built; bash starts each line).
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// isTerminal reports whether f is a terminal.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// cbreak turns off line buffering and echo on the terminal stdin is, so one
// key press is read at once. The returned function turns both back on.
func cbreak(stdin *os.File) (restore func(), ok bool) {
	set := exec.Command("stty", "-icanon", "-echo")
	set.Stdin = stdin
	if err := set.Run(); err != nil {
		return func() {}, false
	}
	return func() {
		back := exec.Command("stty", "icanon", "echo")
		back.Stdin = stdin
		_ = back.Run()
	}, true
}

// terminate sends SIGTERM to one process.
func terminate(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }

// killGroup sends SIGKILL to the process group pid leads.
func killGroup(pid int) error { return syscall.Kill(-pid, syscall.SIGKILL) }

// alive reports whether a process with this pid still exists and is not a
// zombie waiting for its parent.
func alive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return false
	}
	stat := strings.TrimSpace(string(out))
	return stat != "" && !strings.HasPrefix(stat, "Z")
}

// ownGroup starts cmd in a process group of its own, which the terminal's
// Ctrl-C does not reach: the tour stops it itself.
func ownGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
