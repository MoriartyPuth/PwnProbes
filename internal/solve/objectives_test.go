package solve

import "testing"

// EstablishLeak is met by an established leak primitive; a confirmed format
// string is partial (Confirmed); nothing is Inconclusive.
func TestEstablishLeakObjective(t *testing.T) {
	o := EstablishLeak{}
	withLeak := Outcome{Primitives: []Primitive{{Kind: PrimitiveLeak}}}
	if got := o.Verify(withLeak).Status; got != StatusObjectiveMet {
		t.Errorf("leak primitive: status=%s, want objective_met", got)
	}
	withFmt := Outcome{Findings: []Finding{{Kind: FindingFormatString, Status: StatusConfirmed}}}
	if got := o.Verify(withFmt).Status; got != StatusConfirmed {
		t.Errorf("confirmed fmt: status=%s, want confirmed", got)
	}
	if got := o.Verify(Outcome{}).Status; got != StatusInconclusive {
		t.Errorf("empty: status=%s, want inconclusive", got)
	}
}

// DemonstrateControl is met by a solve via a control-flow technique; a crash
// with no solve is only Observed; a non-control solve (a leak) is Inconclusive.
func TestDemonstrateControlObjective(t *testing.T) {
	o := DemonstrateControl{}
	solveControl := Outcome{Solved: true, WinningStrategy: "ret2plt"}
	if got := o.Verify(solveControl).Status; got != StatusObjectiveMet {
		t.Errorf("control solve: status=%s, want objective_met", got)
	}
	crashOnly := Outcome{Findings: []Finding{{Kind: FindingCrash, Status: StatusObserved}}}
	if got := o.Verify(crashOnly).Status; got != StatusObserved {
		t.Errorf("crash only: status=%s, want observed (not promoted)", got)
	}
	leakSolve := Outcome{Solved: true, WinningStrategy: "stack_dump"}
	if got := o.Verify(leakSolve).Status; got != StatusInconclusive {
		t.Errorf("leak solve: status=%s, want inconclusive (not control)", got)
	}
}

// DemonstrateWrite is met only by a write-class solve.
func TestDemonstrateWriteObjective(t *testing.T) {
	o := DemonstrateWrite{}
	if got := o.Verify(Outcome{Solved: true, WinningStrategy: "fmt_got_overwrite"}).Status; got != StatusObjectiveMet {
		t.Errorf("fmt_got solve: status=%s, want objective_met", got)
	}
	if got := o.Verify(Outcome{Solved: true, WinningStrategy: "ret2plt"}).Status; got != StatusInconclusive {
		t.Errorf("ret2plt solve: status=%s, want inconclusive (ret2plt is not a write)", got)
	}
}

// SpawnShell is met only by a shell-spawning solve.
func TestSpawnShellObjective(t *testing.T) {
	o := SpawnShell{}
	if got := o.Verify(Outcome{Solved: true, WinningStrategy: "shellcode"}).Status; got != StatusObjectiveMet {
		t.Errorf("shellcode solve: status=%s, want objective_met", got)
	}
	if got := o.Verify(Outcome{Solved: true, WinningStrategy: "ret2plt"}).Status; got != StatusInconclusive {
		t.Errorf("ret2plt solve: status=%s, want inconclusive (no shell)", got)
	}
}

// An unsolved outcome never reports any objective as met — Solved stays
// authoritative and nothing is promoted without it.
func TestNoObjectiveMetWithoutSolve(t *testing.T) {
	// A crash observed, no solve, no primitives.
	out := Outcome{Findings: []Finding{{Kind: FindingCrash, Status: StatusObserved}}, HighestStatus: StatusObserved}
	for _, v := range EvaluateObjectives(out) {
		if v.Status == StatusObjectiveMet {
			t.Errorf("objective %s reported met without a solve", v.Objective)
		}
	}
}

// EvaluateObjectives returns RecoverFlag first (authoritative) and the full set.
func TestEvaluateObjectivesOrderAndSet(t *testing.T) {
	vs := EvaluateObjectives(Outcome{Flags: []string{"FLAG{x}"}, Solved: true, WinningStrategy: "rop_execve"})
	if len(vs) != 5 {
		t.Fatalf("want 5 objectives, got %d", len(vs))
	}
	if vs[0].Objective != "recover_flag" || vs[0].Status != StatusObjectiveMet {
		t.Errorf("first objective = %+v, want recover_flag/objective_met", vs[0])
	}
	// rop_execve demonstrates control and spawns a shell; it is not a write.
	got := map[string]VerificationStatus{}
	for _, v := range vs {
		got[v.Objective] = v.Status
	}
	if got["demonstrate_control"] != StatusObjectiveMet {
		t.Errorf("demonstrate_control = %s, want objective_met", got["demonstrate_control"])
	}
	if got["spawn_shell"] != StatusObjectiveMet {
		t.Errorf("spawn_shell = %s, want objective_met", got["spawn_shell"])
	}
	if got["demonstrate_write"] != StatusInconclusive {
		t.Errorf("demonstrate_write = %s, want inconclusive (rop_execve is not a write)", got["demonstrate_write"])
	}
}

// CustomPredicate verifies an ad-hoc objective over the outcome.
func TestCustomPredicate(t *testing.T) {
	c := CustomPredicate{Name: "two_flags", Pred: func(o Outcome) bool { return len(o.Flags) >= 2 }}
	if c.ID() != "custom:two_flags" {
		t.Errorf("id = %q", c.ID())
	}
	if c.Verify(Outcome{Flags: []string{"a", "b"}}).Status != StatusObjectiveMet {
		t.Error("predicate should be satisfied by two flags")
	}
	if c.Verify(Outcome{Flags: []string{"a"}}).Status != StatusInconclusive {
		t.Error("predicate should not be satisfied by one flag")
	}
}
