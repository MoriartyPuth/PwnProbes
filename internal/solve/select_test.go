package solve

import "testing"

// A feasible, cheap chain promotes its terminal strategy to the front of the
// non-expensive group, while expensive strategies stay deferred and every other
// relative order is preserved.
func TestApplyCompositionPromotesCheapFeasible(t *testing.T) {
	s := &solver{report: &Report{}}
	reg := s.buildRegistry()
	run, _ := reg.eligible(ModeLocal)

	// A feasible, cheap chain whose terminal step is ret2plt.
	chains := []ComposedChain{{
		Goal: "spawn_shell", Cost: CostCheap, Feasible: true, Reason: "has pop-rdi, stub, string",
		Steps: []ChainStep{{Strategy: "stack_overflow"}, {Strategy: "ret2plt"}},
	}}
	out := s.applyComposition(run, chains)

	// ret2plt is now the first non-expensive strategy.
	if out[0].ID() != "ret2plt" {
		t.Errorf("ret2plt should be promoted to front, got %s", out[0].ID())
	}
	// Expensive strategies remain after all non-expensive ones (PR 6 preserved).
	seenExpensive := false
	for _, st := range out {
		if st.Cost().Expensive {
			seenExpensive = true
		} else if seenExpensive {
			t.Errorf("non-expensive %s appears after an expensive strategy", st.ID())
		}
	}
	// The promotion is recorded with a reason.
	if len(s.report.Selection) != 1 || s.report.Selection[0].Strategy != "ret2plt" {
		t.Errorf("promotion rationale not recorded: %+v", s.report.Selection)
	}
}

// An infeasible chain, or a non-cheap one, does not change the order and records
// nothing (weaker signals stay advisory).
func TestApplyCompositionIgnoresWeakChains(t *testing.T) {
	s := &solver{report: &Report{}}
	reg := s.buildRegistry()
	run, _ := reg.eligible(ModeLocal)
	before := selIDs(run)

	chains := []ComposedChain{
		{Goal: "spawn_shell", Cost: CostCheap, Feasible: false, Steps: []ChainStep{{Strategy: "ret2plt"}}},    // infeasible
		{Goal: "spawn_shell", Cost: CostModerate, Feasible: true, Steps: []ChainStep{{Strategy: "ret2libc"}}}, // not cheap
	}
	out := s.applyComposition(run, chains)
	if !selEqual(before, selIDs(out)) {
		t.Errorf("weak chains should not reorder:\n before %v\n after  %v", before, selIDs(out))
	}
	if len(s.report.Selection) != 0 {
		t.Errorf("no promotion should be recorded, got %+v", s.report.Selection)
	}
}

// Promotion is order-preserving for everything it does not promote.
func TestApplyCompositionStable(t *testing.T) {
	s := &solver{report: &Report{}}
	reg := s.buildRegistry()
	run, _ := reg.eligible(ModeLocal)
	chains := []ComposedChain{{Cost: CostCheap, Feasible: true, Steps: []ChainStep{{Strategy: "ret2plt"}}}}
	out := s.applyComposition(run, chains)

	// Drop ret2plt from both and the remaining order must be identical.
	if got, want := selWithout(selIDs(out), "ret2plt"), selWithout(selIDs(run), "ret2plt"); !selEqual(got, want) {
		t.Errorf("non-promoted order changed:\n got  %v\n want %v", got, want)
	}
}

func selIDs(ss []Strategy) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.ID()
	}
	return out
}

func selEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func selWithout(ss []string, drop string) []string {
	var out []string
	for _, s := range ss {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}
