//go:build !windows

package e2e

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the started process in its own group, so killTree
// can stop wrangler and its children together.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
