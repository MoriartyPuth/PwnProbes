package solve

import (
	"strings"
	"testing"

	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
)

// A missing or unreadable target resolves to an empty (infeasible) resolution
// rather than erroring, so planning stays side-effect-free and robust.
func TestResolveRet2pltMissingTarget(t *testing.T) {
	bin := inspect.Report{Bits: 64, Protections: map[string]inspect.Evidence{"pie": {Status: "disabled"}}}
	res := resolveRet2pltFrom(bin, "/nonexistent/vuln")
	if res.Feasible() || res.HasPopRDI || len(res.Calls) != 0 {
		t.Errorf("missing target should give an empty resolution, got %+v", res)
	}
}

// A PIE target is not resolvable for ret2plt (addresses are not fixed).
func TestResolveRet2pltRejectsPIE(t *testing.T) {
	bin := inspect.Report{Bits: 64, Protections: map[string]inspect.Evidence{"pie": {Status: "enabled"}}}
	if resolveRet2pltFrom(bin, "/any").HasPopRDI {
		t.Error("PIE target should not resolve ret2plt gadgets")
	}
}

// The plan built from a feasible resolution carries the concrete gadget, string,
// and stub addresses, and is marked feasible.
func TestPlanRet2pltWithResolvedAddresses(t *testing.T) {
	tc := tcWith(64, false, nil, nil)
	res := Ret2pltResolution{
		PopRDI: 0x401283, HasPopRDI: true, Ret: 0x40101a, HasRet: true,
		Calls:   []pltCall{{name: "system", addr: 0x401050}},
		Strings: []strEntry{{addr: 0x402004, text: "/bin/sh"}},
	}
	p := planRet2pltWith(tc, res)
	if !p.Feasible {
		t.Fatalf("plan should be feasible with full resolution, requires=%+v", p.Requires)
	}
	joined := ""
	for _, s := range p.Steps {
		joined += s.Action + "\n"
	}
	for _, want := range []string{"0x401283", "0x401050", "/bin/sh", "0x402004"} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan steps should mention %q (concrete address/string):\n%s", want, joined)
		}
	}
}

// Without a resolved gadget/stub/string, the plan is infeasible and the unmet
// requirement is named — not silently dropped.
func TestPlanRet2pltWithInfeasible(t *testing.T) {
	tc := tcWith(64, false, nil, nil)
	p := planRet2pltWith(tc, Ret2pltResolution{}) // nothing resolved
	if p.Feasible {
		t.Fatal("empty resolution should give an infeasible plan")
	}
	if !hasUnmet(p, "pop rdi; ret gadget") || !hasUnmet(p, "callable system/exec* PLT stub") || !hasUnmet(p, "in-binary command string") {
		t.Errorf("unmet resolution requirements should be visible: %+v", p.Requires)
	}
}

// Feasible reflects the minimum material a ret2plt chain needs.
func TestRet2pltResolutionFeasible(t *testing.T) {
	full := Ret2pltResolution{HasPopRDI: true, Calls: []pltCall{{}}, Strings: []strEntry{{}}}
	if !full.Feasible() {
		t.Error("full resolution should be feasible")
	}
	for _, partial := range []Ret2pltResolution{
		{Calls: []pltCall{{}}, Strings: []strEntry{{}}}, // no gadget
		{HasPopRDI: true, Strings: []strEntry{{}}},      // no stub
		{HasPopRDI: true, Calls: []pltCall{{}}},         // no string
	} {
		if partial.Feasible() {
			t.Errorf("partial resolution should not be feasible: %+v", partial)
		}
	}
}
