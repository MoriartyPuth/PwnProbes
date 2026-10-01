//go:build !linux

package session

import "os/exec"

func configureProc(cmd *exec.Cmd) {}
