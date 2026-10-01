//go:build !linux

package runner

import (
	"os"
	"os/exec"
)

func configure(cmd *exec.Cmd)              {}
func killGroup(cmd *exec.Cmd) error        { return nil }
func signal(state *os.ProcessState) string { return "" }
