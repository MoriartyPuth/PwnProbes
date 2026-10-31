package repl

import (
	"context"
	"strings"
	"testing"

	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
	"github.com/MoriartyPuth/PwnProbes/internal/solve"
)

// fakeEngine returns canned reports and records calls, so the shell is tested
// without an ELF file or any target execution.
type fakeEngine struct {
	analyzeN, solveN int
	libc             string
}

func (f *fakeEngine) Analyze(context.Context) (solve.Report, error) {
	f.analyzeN++
	tc := &solve.TargetContext{
		Target:       solve.Target{Path: "vuln", SHA256: "abc", Architecture: "amd64", Bits: 64, Mode: "local"},
		Capabilities: solve.Capabilities{NX: true, ExecutionSupported: true},
	}
	return solve.Report{
		Context: tc,
		Plans: []solve.Plan{
			{ID: "ret2plt", Strategy: "ret2plt", Feasible: true, Risk: solve.RiskLow,
				Steps:    []solve.Step{{Index: 1, Action: "load rdi"}},
				Requires: []solve.Requirement{{Name: "non-PIE", Met: true}}},
		},
	}, nil
}

func (f *fakeEngine) Solve(context.Context) (solve.Report, error) {
	f.solveN++
	tc := &solve.TargetContext{
		Target:     solve.Target{Path: "vuln", SHA256: "abc", Bits: 64},
		Findings:   []solve.Finding{{Kind: solve.FindingFlag, Status: solve.StatusObjectiveMet, Source: "ret2plt"}},
		Primitives: []solve.Primitive{{Kind: solve.PrimitiveCall, Status: solve.StatusExploitabilityEstablished, Source: "ret2plt"}},
	}
	return solve.Report{
		Solved:     true,
		Flags:      []string{"FLAG{x}"},
		Context:    tc,
		Objectives: []solve.Verification{{Objective: "recover_flag", Status: solve.StatusObjectiveMet}},
	}, nil
}

func (f *fakeEngine) SetLibc(p string) { f.libc = p }
func (f *fakeEngine) Libc() string     { return f.libc }

// drive runs a newline-separated script through the shell and returns its output.
func drive(t *testing.T, eng Engine, script string) string {
	t.Helper()
	var out strings.Builder
	if err := Run(context.Background(), strings.NewReader(script), &out, eng); err != nil {
		t.Fatalf("Run error: %v", err)
	}
	return out.String()
}

// analyze then plan: the shell drives Analyze once and can inspect a plan by id.
func TestShellAnalyzeAndInspectPlan(t *testing.T) {
	eng := &fakeEngine{}
	out := drive(t, eng, "analyze\nplan ret2plt\nquit\n")
	if eng.analyzeN == 0 {
		t.Error("analyze should call the engine")
	}
	if !strings.Contains(out, "1 candidate plan") {
		t.Errorf("analyze output missing plan count:\n%s", out)
	}
	if !strings.Contains(out, "load rdi") || !strings.Contains(out, "requirement [met] non-PIE") {
		t.Errorf("plan inspection missing steps/requirements:\n%s", out)
	}
}

// Injecting knowledge invalidates plans: the next plan/analyze re-queries the
// engine rather than reusing the stale analysis.
func TestShellKnowledgeInvalidatesPlans(t *testing.T) {
	eng := &fakeEngine{}
	out := drive(t, eng, "analyze\nknowledge libc ./libc.so.6\nplans\nquit\n")
	if eng.libc != "./libc.so.6" {
		t.Errorf("libc not injected: %q", eng.libc)
	}
	if eng.analyzeN != 2 {
		t.Errorf("knowledge change should force re-analysis: analyzeN=%d, want 2", eng.analyzeN)
	}
	if !strings.Contains(out, "plans invalidated") || !strings.Contains(out, "recomputing plans") {
		t.Errorf("expected invalidation + recompute messages:\n%s", out)
	}
}

// solve runs the engine and objective/finding/primitive evidence is inspectable.
func TestShellSolveAndEvidence(t *testing.T) {
	eng := &fakeEngine{}
	out := drive(t, eng, "solve\nfindings\nprimitives\nobjectives\nquit\n")
	if eng.solveN != 1 {
		t.Errorf("solve should call the engine once, got %d", eng.solveN)
	}
	for _, want := range []string{"SOLVED: [FLAG{x}]", "flag", "call", "recover_flag", "objective_met"} {
		if !strings.Contains(out, want) {
			t.Errorf("solve/evidence output missing %q:\n%s", want, out)
		}
	}
}

// Unknown commands are reported, not fatal; quit ends the loop.
func TestShellUnknownCommand(t *testing.T) {
	out := drive(t, &fakeEngine{}, "bogus\nquit\n")
	if !strings.Contains(out, `unknown command "bogus"`) {
		t.Errorf("expected unknown-command message:\n%s", out)
	}
}

// open resumes a saved workspace through the engine-independent loader.
func TestShellOpenWorkspace(t *testing.T) {
	// Save a workspace to a temp file first.
	w := solve.WorkspaceFromReport(&solve.Report{
		Binary:  inspect.Report{SHA256: "zzz"},
		Solved:  true,
		Flags:   []string{"FLAG{y}"},
		Context: &solve.TargetContext{Target: solve.Target{Path: "vuln", SHA256: "zzz"}},
	})
	path := t.TempDir() + "/w.json"
	if err := w.Save(path); err != nil {
		t.Fatal(err)
	}
	out := drive(t, &fakeEngine{}, "open "+path+"\nquit\n")
	if !strings.Contains(out, "resumed workspace") || !strings.Contains(out, "sha256=zzz") {
		t.Errorf("open did not resume the workspace:\n%s", out)
	}
}
