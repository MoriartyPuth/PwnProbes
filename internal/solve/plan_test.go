package solve

import (
	"testing"

	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
)

// tcWith builds a TargetContext with chosen capabilities for plan-gating tests,
// without any target or execution.
func tcWith(bits int, pie bool, funcs []inspect.Symbol, imports []string) *TargetContext {
	bin := inspect.Report{
		Bits:               bits,
		ExecutionSupported: true,
		Functions:          funcs,
		Imports:            imports,
		Protections: map[string]inspect.Evidence{
			"pie": {Status: map[bool]string{true: "enabled", false: "disabled"}[pie]},
		},
	}
	return newTargetContext(bin, "/tmp/vuln", "local", "")
}

// A ret2win plan is feasible on a 64-bit non-PIE target with a win function, and
// declares the primitives it would produce.
func TestPlanRopRet2winArgsFeasible(t *testing.T) {
	tc := tcWith(64, false, []inspect.Symbol{{Name: "win", Address: "0x401200"}}, nil)
	p := planRopRet2winArgs(tc)
	if !p.Feasible {
		t.Fatalf("expected feasible plan, requires=%+v", p.Requires)
	}
	if len(p.Steps) == 0 {
		t.Error("plan should have steps")
	}
	if !containsKind(p.Produces, PrimitiveControl) {
		t.Errorf("ret2win should produce control, got %v", p.Produces)
	}
}

// Under PIE the same plan is infeasible, with the non-PIE requirement unmet and
// visible — the strategy is not silently dropped.
func TestPlanRopRet2winArgsInfeasibleUnderPIE(t *testing.T) {
	tc := tcWith(64, true, []inspect.Symbol{{Name: "win", Address: "0x1200"}}, nil)
	p := planRopRet2winArgs(tc)
	if p.Feasible {
		t.Fatal("plan should be infeasible under PIE")
	}
	if !hasUnmet(p, "non-PIE (fixed addresses)") {
		t.Errorf("expected the non-PIE requirement to be unmet and visible: %+v", p.Requires)
	}
}

// ret2plt's plan is now resolution-driven: against a target that cannot be
// resolved (no real ELF here), it is infeasible with the resolved requirements
// unmet. Feasibility from a real resolution is covered in resolve_test.go.
func TestPlanRet2pltResolutionDriven(t *testing.T) {
	p := planRet2plt(tcWith(64, false, nil, []string{"printf", "system"}))
	if p.Feasible {
		t.Error("ret2plt should be infeasible when gadgets/strings cannot be resolved from the target")
	}
	if !hasUnmet(p, "pop rdi; ret gadget") {
		t.Errorf("the resolved gadget requirement should be unmet and visible: %+v", p.Requires)
	}
}

// partial_overwrite is the PIE case: feasible only under PIE.
func TestPlanPartialOverwritePIEOnly(t *testing.T) {
	if !planPartialOverwrite(tcWith(64, true, nil, nil)).Feasible {
		t.Error("partial_overwrite should be feasible under PIE")
	}
	if planPartialOverwrite(tcWith(64, false, nil, nil)).Feasible {
		t.Error("partial_overwrite should be infeasible without PIE")
	}
}

// collectPlans returns plans only for plannable strategies, in eligible order,
// and never for execution-only ones (shellcode, angr, ret2libc, canary, heap).
func TestCollectPlansOnlyPlannable(t *testing.T) {
	s := &solver{tc: tcWith(64, false, []inspect.Symbol{{Name: "win", Address: "0x401200"}}, []string{"system"})}
	reg := s.buildRegistry()
	plans := s.collectPlans(ModeLocal, reg)
	if len(plans) == 0 {
		t.Fatal("expected some plans")
	}
	got := map[string]bool{}
	for _, p := range plans {
		got[p.Strategy] = true
		if p.Cost.Tier == "" {
			t.Errorf("plan %s missing cost (not finalized)", p.Strategy)
		}
		if p.Risk == "" {
			t.Errorf("plan %s missing risk", p.Strategy)
		}
	}
	for _, want := range []string{"stack_overwrite", "rop_ret2win_args", "rop_execve", "ret2plt", "rop_planner", "partial_overwrite"} {
		if !got[want] {
			t.Errorf("expected a plan for %s", want)
		}
	}
	for _, exec := range []string{"shellcode", "ret2libc", "canary_ret2win", "heap_uaf", "angr_logic"} {
		if got[exec] {
			t.Errorf("execution-only strategy %s must not produce a plan", exec)
		}
	}
}

// The catalog marks exactly the plannable strategies, and leaves the rest
// explicitly execution-only.
func TestCatalogPlannableFlag(t *testing.T) {
	plannable := map[string]bool{}
	execOnly := map[string]bool{}
	for _, st := range Catalog() {
		if st.Plannable {
			plannable[st.ID] = true
		} else {
			execOnly[st.ID] = true
		}
	}
	if !plannable["ret2plt"] || !plannable["rop_planner"] {
		t.Errorf("ret2plt/rop_planner should be plannable: %v", plannable)
	}
	if !execOnly["shellcode"] || !execOnly["angr_logic"] || !execOnly["format_string"] {
		t.Errorf("shellcode/angr_logic/format_string should be execution-only: %v", execOnly)
	}
}

func containsKind(ks []PrimitiveKind, want PrimitiveKind) bool {
	for _, k := range ks {
		if k == want {
			return true
		}
	}
	return false
}

func hasUnmet(p Plan, name string) bool {
	for _, r := range p.Requires {
		if r.Name == name && !r.Met {
			return true
		}
	}
	return false
}
