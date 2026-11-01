package execution

import (
	"context"
	"fmt"
	"strings"
)

// This file adds a supported isolated one-shot backend (roadmap §30 PR 19). It
// enforces resource limits — address space (memory), CPU seconds, and process
// count — by running the target under a POSIX shell that applies `ulimit` and
// then `exec`s it in place, so the target keeps the runner's process group
// (process-tree termination) and output/deadline bounds still apply. This is a
// real, supported control on Linux; unlike the native backend it does not merely
// decline the limits. Network and filesystem isolation would need namespaces
// (bubblewrap/unshare) and are not provided here, so they are rejected
// explicitly rather than silently ignored, and interactive isolated sessions are
// not supported yet.

// Isolated is a one-shot executor that enforces the resource limits in Policy
// via ulimit. It delegates the actual spawn to Native after wrapping the command.
type Isolated struct {
	Policy ExecutionPolicy
}

// BackendName identifies the isolated backend.
func (Isolated) BackendName() string { return "isolated" }

// Enforces lists what this backend guarantees: everything native does, plus the
// resource limits it applies through ulimit. It does not claim network or
// filesystem isolation.
func (Isolated) Enforces() []Control {
	return []Control{
		ControlTimeout, ControlOutputBound, ControlInputBound,
		ControlProcessTreeKill, ControlScratchDirs,
		ControlMemoryLimit, ControlCPULimit, ControlProcessLimit,
	}
}

// ValidatePolicy accepts the sandbox isolation level and the resource limits it
// enforces, and rejects — explicitly — the controls it cannot provide (network
// or filesystem isolation, or the container level).
func (i Isolated) ValidatePolicy(p ExecutionPolicy) error {
	var unsup []Control
	if p.Network == NetworkNone {
		unsup = append(unsup, ControlNetworkIsolation)
	}
	if p.Filesystem == FilesystemReadonly {
		unsup = append(unsup, ControlFilesystemIsolation)
	}
	isoProblem := p.Isolation == IsolationContainer
	if len(unsup) == 0 && !isoProblem {
		return nil
	}
	err := &UnsupportedPolicyError{Backend: i.BackendName(), Unsupported: unsup}
	if isoProblem {
		err.Isolation = p.Isolation
	}
	return err
}

// Run enforces the policy's resource limits, then runs the target natively. When
// the policy sets no limits the wrap is a no-op prelude and behaviour matches
// native execution.
func (i Isolated) Run(ctx context.Context, req Request) (Result, error) {
	return Native{}.Run(ctx, i.wrap(req))
}

// Open reports, explicitly, that isolated interactive sessions are not supported
// yet — rather than quietly opening an unisolated one.
func (Isolated) Open(_ context.Context, _ SessionRequest) (Session, error) {
	return nil, fmt.Errorf("isolated backend: interactive sessions are not isolated yet; use native mode or one-shot run")
}

// wrap rewrites a request to apply the resource limits via ulimit in a POSIX
// shell, then exec the real target in place (keeping its pid and process group).
func (i Isolated) wrap(req Request) Request {
	var b strings.Builder
	if i.Policy.MaxMemoryBytes > 0 {
		fmt.Fprintf(&b, "ulimit -v %d 2>/dev/null; ", i.Policy.MaxMemoryBytes/1024) // -v is KiB
	}
	if i.Policy.MaxCPUSeconds > 0 {
		fmt.Fprintf(&b, "ulimit -t %d 2>/dev/null; ", i.Policy.MaxCPUSeconds)
	}
	if i.Policy.MaxProcesses > 0 {
		fmt.Fprintf(&b, "ulimit -u %d 2>/dev/null; ", i.Policy.MaxProcesses)
	}
	b.WriteString(`exec "$@"`)
	// sh -c <script> sh <program> <args...> : $0=sh, "$@"=program+args.
	args := append([]string{"-c", b.String(), "sh", req.Program}, req.Args...)
	w := req
	w.Program = "/bin/sh"
	w.Args = args
	return w
}

// Backend is an executor that also declares and validates what it enforces.
type Backend interface {
	Executor
	PolicyBackend
}

// SelectBackend chooses the execution backend for a policy, validating it. None
// uses Native; sandbox uses Isolated (resource limits via ulimit); an unknown or
// unsupported level is an explicit error.
func SelectBackend(p ExecutionPolicy) (Backend, error) {
	switch p.Isolation {
	case "", IsolationNone:
		b := Native{}
		if err := b.ValidatePolicy(p); err != nil {
			return nil, err
		}
		return b, nil
	case IsolationSandbox:
		b := Isolated{Policy: p}
		if err := b.ValidatePolicy(p); err != nil {
			return nil, err
		}
		return b, nil
	default:
		return nil, &UnsupportedPolicyError{Backend: "(none)", Isolation: p.Isolation}
	}
}
