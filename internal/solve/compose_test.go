package solve

import "testing"

func chainByLast(chains []ComposedChain, lastStrategy string) (ComposedChain, bool) {
	for _, c := range chains {
		if len(c.Steps) > 0 && c.Steps[len(c.Steps)-1].Strategy == lastStrategy {
			return c, true
		}
	}
	return ComposedChain{}, false
}

// With full ret2plt material resolved, the direct ret2plt chain is feasible; the
// ret2libc chain is not, because no libc leak is available.
func TestComposeRet2pltFeasibleNoLeak(t *testing.T) {
	tc := &TargetContext{Target: Target{Bits: 64}}
	res := Ret2pltResolution{PopRDI: 0x401283, HasPopRDI: true,
		Calls: []pltCall{{name: "system", addr: 0x401050}}, Strings: []strEntry{{addr: 0x402004, text: "/bin/sh"}}}
	chains := composeChains(tc, res)

	r2p, ok := chainByLast(chains, "ret2plt")
	if !ok || !r2p.Feasible {
		t.Fatalf("ret2plt chain should be feasible: %+v", chains)
	}
	// The composed chain names the concrete resolved addresses.
	if !containsSub(r2p.Steps[len(r2p.Steps)-1].Via, "0x401050") {
		t.Errorf("ret2plt step should reference the resolved stub: %q", r2p.Steps[len(r2p.Steps)-1].Via)
	}
	r2l, _ := chainByLast(chains, "ret2libc")
	if r2l.Feasible {
		t.Error("ret2libc chain should not be feasible without a libc leak")
	}
}

// Cross-strategy composition: a confirmed format string makes the leak step
// satisfied, so the ret2libc chain becomes feasible (given pop-rdi) — the leak
// producer feeds the leak consumer.
func TestComposeRet2libcFromFormatStringLeak(t *testing.T) {
	tc := &TargetContext{Target: Target{Bits: 64}}
	tc.addFinding(Finding{ID: "detect/format_string/0", Kind: FindingFormatString, Status: StatusConfirmed, Source: "detect"})
	res := Ret2pltResolution{PopRDI: 0x401283, HasPopRDI: true} // pop-rdi, but no PLT stub/string

	chains := composeChains(tc, res)
	r2l, ok := chainByLast(chains, "ret2libc")
	if !ok || !r2l.Feasible {
		t.Fatalf("ret2libc chain should be feasible once a format-string leak is available: %+v", r2l)
	}
	// The first step is the leak producer, and it is satisfied.
	if r2l.Steps[0].Produces != PrimitiveLeak || !r2l.Steps[0].Satisfied {
		t.Errorf("ret2libc chain should start with a satisfied leak step: %+v", r2l.Steps)
	}
	// ret2plt, lacking a stub/string, is not feasible here.
	if r2p, _ := chainByLast(chains, "ret2plt"); r2p.Feasible {
		t.Error("ret2plt chain should be infeasible without a stub/string")
	}
}

// An established libc leak in Knowledge is reused by the ret2libc chain rather
// than requiring a fresh leak.
func TestComposeReusesKnownLibc(t *testing.T) {
	tc := &TargetContext{Target: Target{Bits: 64},
		Knowledge: Knowledge{Libc: &LibraryInfo{Path: "libc.so.6", Resolved: true}}}
	res := Ret2pltResolution{PopRDI: 0x1, HasPopRDI: true}
	r2l, _ := chainByLast(composeChains(tc, res), "ret2libc")
	if !r2l.Feasible || !containsSub(r2l.Reason, "reuses the leak") {
		t.Errorf("known libc should make ret2libc feasible and reused: %+v", r2l)
	}
}

// Composition is deterministic: same context, same chains in the same order.
func TestComposeDeterministic(t *testing.T) {
	tc := &TargetContext{Target: Target{Bits: 64}}
	res := Ret2pltResolution{HasPopRDI: true, Calls: []pltCall{{name: "system", addr: 1}}, Strings: []strEntry{{text: "x", addr: 2}}}
	a, b := composeChains(tc, res), composeChains(tc, res)
	if len(a) != len(b) || len(a) == 0 {
		t.Fatalf("unexpected chain counts %d/%d", len(a), len(b))
	}
	for i := range a {
		if a[i].Steps[len(a[i].Steps)-1].Strategy != b[i].Steps[len(b[i].Steps)-1].Strategy {
			t.Errorf("chain order not deterministic at %d", i)
		}
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
