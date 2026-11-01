package execution

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Isolated declares the resource-limit controls it enforces, and still does not
// claim network/filesystem isolation.
func TestIsolatedEnforces(t *testing.T) {
	has := map[Control]bool{}
	for _, c := range (Isolated{}).Enforces() {
		has[c] = true
	}
	for _, want := range []Control{ControlMemoryLimit, ControlCPULimit, ControlProcessLimit, ControlProcessTreeKill, ControlTimeout} {
		if !has[want] {
			t.Errorf("isolated should enforce %s", want)
		}
	}
	for _, no := range []Control{ControlNetworkIsolation, ControlFilesystemIsolation} {
		if has[no] {
			t.Errorf("isolated must not claim %s without namespace support", no)
		}
	}
}

// Isolated accepts resource limits and the sandbox level, but rejects network/
// filesystem isolation and the container level explicitly.
func TestIsolatedValidate(t *testing.T) {
	ok := DefaultPolicy(time.Second)
	ok.Isolation = IsolationSandbox
	ok.MaxMemoryBytes = 1 << 26
	if err := (Isolated{}).ValidatePolicy(ok); err != nil {
		t.Errorf("sandbox + memory limit should validate, got %v", err)
	}
	bad := DefaultPolicy(time.Second)
	bad.Isolation = IsolationSandbox
	bad.Network = NetworkNone
	var ue *UnsupportedPolicyError
	if err := (Isolated{}).ValidatePolicy(bad); !errors.As(err, &ue) {
		t.Errorf("network isolation should be rejected, got %v", err)
	}
}

// wrap builds a `sh -c 'ulimit ...; exec "$@"' sh <program> <args>` command that
// applies the limits and execs the target in place.
func TestIsolatedWrap(t *testing.T) {
	i := Isolated{Policy: ExecutionPolicy{MaxMemoryBytes: 64 << 20, MaxCPUSeconds: 3, MaxProcesses: 8}}
	w := i.wrap(Request{Program: "/tmp/vuln", Args: []string{"a"}, Timeout: time.Second})
	if w.Program != "/bin/sh" {
		t.Fatalf("wrapped program = %q, want /bin/sh", w.Program)
	}
	script := w.Args[1]
	for _, want := range []string{"ulimit -v 65536", "ulimit -t 3", "ulimit -u 8", `exec "$@"`} {
		if !strings.Contains(script, want) {
			t.Errorf("ulimit script missing %q: %s", want, script)
		}
	}
	// The target and its args follow the "sh" $0 placeholder.
	if w.Args[len(w.Args)-2] != "/tmp/vuln" || w.Args[len(w.Args)-1] != "a" {
		t.Errorf("wrapped args should end with the target + its args: %v", w.Args)
	}
	// No limits -> prelude is just the exec, so behaviour matches native.
	plain := (Isolated{}).wrap(Request{Program: "/tmp/vuln"})
	if plain.Args[1] != `exec "$@"` {
		t.Errorf("no-limit wrap should be a bare exec, got %q", plain.Args[1])
	}
}

// SelectBackend maps isolation levels to backends and rejects unknown ones.
func TestSelectBackend(t *testing.T) {
	none, err := SelectBackend(DefaultPolicy(time.Second))
	if err != nil || none.BackendName() != "native" {
		t.Errorf("none -> native, got %v / %v", backendName(none), err)
	}
	sb := DefaultPolicy(time.Second)
	sb.Isolation = IsolationSandbox
	s, err := SelectBackend(sb)
	if err != nil || s.BackendName() != "isolated" {
		t.Errorf("sandbox -> isolated, got %v / %v", backendName(s), err)
	}
	ct := DefaultPolicy(time.Second)
	ct.Isolation = IsolationContainer
	if _, err := SelectBackend(ct); err == nil {
		t.Error("container level should be an explicit error (no backend)")
	}
}

func backendName(b Backend) string {
	if b == nil {
		return "<nil>"
	}
	return b.BackendName()
}
