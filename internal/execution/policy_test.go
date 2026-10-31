package execution

import (
	"errors"
	"testing"
	"time"
)

// The default policy requests only what native execution enforces, so it must
// validate cleanly — ordinary solves are unaffected.
func TestNativeValidatesDefaultPolicy(t *testing.T) {
	if err := (Native{}).ValidatePolicy(DefaultPolicy(2 * time.Second)); err != nil {
		t.Fatalf("default policy should validate on native, got %v", err)
	}
}

// Native enforces timeout, bounds, process-tree kill, and scratch dirs — and
// nothing more. It must not claim any isolation control.
func TestNativeEnforcesHonestSet(t *testing.T) {
	has := map[Control]bool{}
	for _, c := range (Native{}).Enforces() {
		has[c] = true
	}
	for _, want := range []Control{ControlTimeout, ControlOutputBound, ControlInputBound, ControlProcessTreeKill, ControlScratchDirs} {
		if !has[want] {
			t.Errorf("native should enforce %s", want)
		}
	}
	for _, notClaimed := range []Control{ControlMemoryLimit, ControlCPULimit, ControlProcessLimit, ControlNetworkIsolation, ControlFilesystemIsolation} {
		if has[notClaimed] {
			t.Errorf("native must not claim to enforce %s (it is not a sandbox)", notClaimed)
		}
	}
}

// Each isolation control a policy can request is rejected on native, with the
// control named — never silently ignored.
func TestNativeRejectsUnenforceableControls(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ExecutionPolicy)
		want Control
	}{
		{"memory", func(p *ExecutionPolicy) { p.MaxMemoryBytes = 1 << 20 }, ControlMemoryLimit},
		{"cpu", func(p *ExecutionPolicy) { p.MaxCPUSeconds = 1 }, ControlCPULimit},
		{"processes", func(p *ExecutionPolicy) { p.MaxProcesses = 4 }, ControlProcessLimit},
		{"network", func(p *ExecutionPolicy) { p.Network = NetworkNone }, ControlNetworkIsolation},
		{"filesystem", func(p *ExecutionPolicy) { p.Filesystem = FilesystemReadonly }, ControlFilesystemIsolation},
	}
	for _, c := range cases {
		p := DefaultPolicy(time.Second)
		c.mut(&p)
		err := (Native{}).ValidatePolicy(p)
		var ue *UnsupportedPolicyError
		if !errors.As(err, &ue) {
			t.Errorf("%s: want UnsupportedPolicyError, got %v", c.name, err)
			continue
		}
		found := false
		for _, u := range ue.Unsupported {
			if u == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: error should name %s, got %v", c.name, c.want, ue.Unsupported)
		}
	}
}

// A requested isolation level native cannot provide is rejected and named.
func TestNativeRejectsIsolationLevel(t *testing.T) {
	for _, lvl := range []IsolationLevel{IsolationSandbox, IsolationContainer} {
		p := DefaultPolicy(time.Second)
		p.Isolation = lvl
		err := (Native{}).ValidatePolicy(p)
		var ue *UnsupportedPolicyError
		if !errors.As(err, &ue) {
			t.Fatalf("isolation %s should be rejected, got %v", lvl, err)
		}
		if ue.Isolation != lvl {
			t.Errorf("error should record isolation %s, got %s", lvl, ue.Isolation)
		}
		if !contains(err.Error(), "isolation="+string(lvl)) {
			t.Errorf("error message should mention the isolation level: %q", err.Error())
		}
	}
}

// Summarize reports the backend, its enforced controls, and the policy.
func TestSummarize(t *testing.T) {
	s := Summarize(Native{}, DefaultPolicy(3*time.Second))
	if s.Backend != "native" || len(s.Enforced) == 0 || s.Policy.Timeout != 3*time.Second {
		t.Errorf("summary wrong: %+v", s)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
