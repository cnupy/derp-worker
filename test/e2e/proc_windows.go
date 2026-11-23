package e2e

import (
	"fmt"
	"os/exec"
)

func setProcessGroup(cmd *exec.Cmd) {}

// killTree stops the process the test started and its children (wrangler
// starts workerd and esbuild) by the PID the test holds.
func killTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	exec.Command("taskkill", "/T", "/F", "/PID", fmt.Sprint(cmd.Process.Pid)).Run()
}
