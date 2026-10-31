package execution

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

// This file models an execution policy and what a backend can enforce (roadmap
// §13, §24). It does not change how targets run: the Native backend keeps its
// existing behavior. What it adds is honesty about isolation — the native runner
// is explicitly "not a security sandbox", so a policy that asks for isolation it
// cannot provide is rejected with a clear unsupported-policy error rather than
// silently ignored. Keeping native execution for trusted CTF labs is the point;
// a sandbox/container backend is a future addition that would enforce the rest.

// Control is a single enforceable execution control. A backend declares the set
// it can enforce; a policy requesting any control outside that set is rejected.
type Control string

const (
	ControlTimeout             Control = "timeout"           // wall-clock deadline + cancellation
	ControlOutputBound         Control = "output_bound"      // cap captured stdout/stderr
	ControlInputBound          Control = "input_bound"       // cap stdin size
	ControlProcessTreeKill     Control = "process_tree_kill" // kill the whole process group on exit/timeout
	ControlScratchDirs         Control = "scratch_dirs"      // HOME/TMPDIR point at a disposable directory
	ControlMemoryLimit         Control = "memory_limit"
	ControlCPULimit            Control = "cpu_limit"
	ControlProcessLimit        Control = "process_limit"
	ControlNetworkIsolation    Control = "network_isolation"
	ControlFilesystemIsolation Control = "filesystem_isolation"
)

// IsolationLevel is the coarse isolation a policy asks for.
type IsolationLevel string

const (
	IsolationNone      IsolationLevel = "none"      // host privileges; working-dir separation only
	IsolationSandbox   IsolationLevel = "sandbox"   // a supported sandbox backend
	IsolationContainer IsolationLevel = "container" // a container backend
)

// NetworkPolicy and FilesystemPolicy bound a locally executed target.
type NetworkPolicy string

const (
	NetworkInherit NetworkPolicy = "inherit" // target shares host network (native default)
	NetworkNone    NetworkPolicy = "none"    // no network (needs isolation)
)

type FilesystemPolicy string

const (
	FilesystemScratch  FilesystemPolicy = "scratch"  // scratch HOME/TMPDIR, host FS otherwise (native default)
	FilesystemReadonly FilesystemPolicy = "readonly" // read-only host FS (needs isolation)
)

// ExecutionPolicy is the requested execution constraints (roadmap §13). The zero
// value is not meaningful; use DefaultPolicy. A control left at its zero/default
// value is not requested and so is never a reason to reject.
type ExecutionPolicy struct {
	Timeout        time.Duration    `json:"timeout"`
	MaxOutputBytes int              `json:"max_output_bytes"`
	MaxMemoryBytes uint64           `json:"max_memory_bytes,omitempty"`
	MaxCPUSeconds  int              `json:"max_cpu_seconds,omitempty"`
	MaxProcesses   int              `json:"max_processes,omitempty"`
	Network        NetworkPolicy    `json:"network"`
	Filesystem     FilesystemPolicy `json:"filesystem"`
	Isolation      IsolationLevel   `json:"isolation"`
}

// DefaultPolicy is what native execution actually enforces today: a wall-clock
// timeout and bounded output, with scratch HOME/TMPDIR and inherited network, no
// isolation. Solve uses it, so default behavior is unchanged.
func DefaultPolicy(timeout time.Duration) ExecutionPolicy {
	return ExecutionPolicy{
		Timeout:        timeout,
		MaxOutputBytes: runner.MaxOutput,
		Network:        NetworkInherit,
		Filesystem:     FilesystemScratch,
		Isolation:      IsolationNone,
	}
}

// requestedControls lists the controls a policy asks a backend to enforce beyond
// the always-present timeout/output bounds.
func (p ExecutionPolicy) requestedControls() []Control {
	var cs []Control
	if p.MaxMemoryBytes > 0 {
		cs = append(cs, ControlMemoryLimit)
	}
	if p.MaxCPUSeconds > 0 {
		cs = append(cs, ControlCPULimit)
	}
	if p.MaxProcesses > 0 {
		cs = append(cs, ControlProcessLimit)
	}
	if p.Network == NetworkNone {
		cs = append(cs, ControlNetworkIsolation)
	}
	if p.Filesystem == FilesystemReadonly {
		cs = append(cs, ControlFilesystemIsolation)
	}
	return cs
}

// UnsupportedPolicyError reports that a backend cannot enforce one or more
// requested controls. It is returned instead of silently degrading, so a caller
// knows the isolation it asked for was not applied.
type UnsupportedPolicyError struct {
	Backend     string
	Unsupported []Control
	Isolation   IsolationLevel // the isolation level asked for, when that is the problem
}

func (e *UnsupportedPolicyError) Error() string {
	parts := make([]string, len(e.Unsupported))
	for i, c := range e.Unsupported {
		parts[i] = string(c)
	}
	if e.Isolation != "" && e.Isolation != IsolationNone {
		parts = append(parts, "isolation="+string(e.Isolation))
	}
	sort.Strings(parts)
	return fmt.Sprintf("backend %q cannot enforce: %s", e.Backend, strings.Join(parts, ", "))
}

// PolicyBackend is a backend that can state and validate what it enforces.
type PolicyBackend interface {
	BackendName() string
	Enforces() []Control
	ValidatePolicy(ExecutionPolicy) error
}

// --- Native backend policy -------------------------------------------------

// BackendName identifies the native backend.
func (Native) BackendName() string { return "native" }

// Enforces lists what native execution actually guarantees. It is honest about
// its limits: it provides no memory/CPU/process/network/filesystem isolation.
func (Native) Enforces() []Control {
	return []Control{
		ControlTimeout, ControlOutputBound, ControlInputBound,
		ControlProcessTreeKill, ControlScratchDirs,
	}
}

// ValidatePolicy returns an UnsupportedPolicyError when the policy asks for a
// control (or an isolation level) native execution cannot enforce. The default
// policy validates cleanly, so ordinary solves are unaffected.
func (n Native) ValidatePolicy(p ExecutionPolicy) error {
	enforced := map[Control]bool{}
	for _, c := range n.Enforces() {
		enforced[c] = true
	}
	var unsup []Control
	for _, c := range p.requestedControls() {
		if !enforced[c] {
			unsup = append(unsup, c)
		}
	}
	isoProblem := p.Isolation != "" && p.Isolation != IsolationNone
	if len(unsup) == 0 && !isoProblem {
		return nil
	}
	err := &UnsupportedPolicyError{Backend: n.BackendName(), Unsupported: unsup}
	if isoProblem {
		err.Isolation = p.Isolation
	}
	return err
}

// PolicySummary is a backend's effective policy, for display in plans, attempts,
// and reports (roadmap §24: make the backend and effective policy visible).
type PolicySummary struct {
	Backend  string          `json:"backend"`
	Enforced []Control       `json:"enforced"`
	Policy   ExecutionPolicy `json:"policy"`
}

// Summarize builds the effective-policy summary for a backend and policy.
func Summarize(b PolicyBackend, p ExecutionPolicy) PolicySummary {
	return PolicySummary{Backend: b.BackendName(), Enforced: b.Enforces(), Policy: p}
}
