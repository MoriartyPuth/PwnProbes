//go:build linux

package execution

import (
	"context"
	"testing"
	"time"
)

// On Linux the isolated backend actually enforces the limits: a CPU-bound target
// under a 1-second CPU limit is killed by the kernel (SIGKILL/SIGXCPU) well
// before the much larger wall-clock deadline — proving the limit is applied, not
// merely declared.
func TestIsolatedCPULimitKills(t *testing.T) {
	i := Isolated{Policy: ExecutionPolicy{MaxCPUSeconds: 1}}
	// A busy loop with no output; without the CPU limit it would run until the
	// 20s wall deadline.
	res, err := i.Run(context.Background(), Request{
		Program: "/bin/sh",
		Args:    []string{"-c", "while :; do :; done"},
		Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatalf("run error: %v", err)
	}
	if res.Outcome == "exited" {
		t.Errorf("CPU-bound target should be killed by the CPU limit, not exit cleanly: %+v", res)
	}
	// Killed by the ~1s CPU rlimit, far below the 20s wall deadline.
	if res.DurationMS > 10_000 {
		t.Errorf("CPU limit did not take effect: ran %dms (wall was 20s)", res.DurationMS)
	}
}
