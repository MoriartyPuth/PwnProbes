//go:build linux

package session

import (
	"os/exec"
	"syscall"
)

// configureProc puts the child in its own process group and makes cancellation
// kill the whole group, so a shell the exploit spawns dies with the connection.
func configureProc(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
