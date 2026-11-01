package solve

import "fmt"

// This file adds primitive composition (roadmap §30 PR 17). The per-strategy
// plans answer "if you run strategy X, here is what it does". Composition answers
// the goal-directed question "to spawn a shell / read the flag, which chain of
// capabilities gets there, and is each link available?" — including chains that
// span two strategies, where one establishes a primitive a later one consumes
// (a format-string leak feeding ret2libc). That cross-strategy dependency is the
// thing single-strategy plans cannot express, and it reuses shared Knowledge so
// a leak is not rediscovered.
//
// A composed chain is a hypothesis. It does not change what executes: the
// existing strategies run and the honest oracle still decides a solve. The
// composer only reasons over static resolution, established primitives, and known
// Knowledge to say which chains are worth trying and why.

// ChainStep is one capability in a composed chain, with how it is obtained and
// whether its statically checkable needs are satisfied now. A step whose needs
// are only verifiable at run time (a reachable overflow) is still marked
// Satisfied with its assumption stated, since there is nothing static to check.
type ChainStep struct {
	Strategy  string        `json:"strategy"`
	Produces  PrimitiveKind `json:"produces"`
	Via       string        `json:"via"`
	Satisfied bool          `json:"satisfied"`
}

// ComposedChain is a goal-directed sequence of capabilities. Steps are ordered
// producer-first (a leak before the chain that consumes it). Feasible is true
// when every step's statically checkable needs hold; an infeasible chain is still
// reported, with the missing link visible in Reason.
type ComposedChain struct {
	Goal     string      `json:"goal"`
	Steps    []ChainStep `json:"steps"`
	Cost     CostTier    `json:"cost"`
	Feasible bool        `json:"feasible"`
	Reason   string      `json:"reason"`
}

// libcLeakAvailable reports whether the run has, or can obtain, a leak that
// resolves libc: an identified libc in Knowledge, a disclosed leak primitive, or
// a confirmed format string that can read one at run time.
func libcLeakAvailable(tc *TargetContext) (bool, string) {
	if tc.Knowledge.Libc != nil && tc.Knowledge.Libc.Resolved {
		return true, "libc identified in knowledge"
	}
	for _, p := range tc.Primitives {
		if p.Kind == PrimitiveLeak {
			return true, "a leak primitive is established"
		}
	}
	for _, f := range tc.Findings {
		if f.Kind == FindingFormatString && f.Status == StatusConfirmed {
			return true, "a confirmed format string can leak libc"
		}
	}
	return false, ""
}

// composeChains builds the candidate capability chains toward a spawned
// shell / flag read, using the ret2plt static resolution (shared with PR 16),
// established primitives, and known Knowledge. It is deterministic: the same
// context yields the same chains in the same order (cheapest, most direct first).
func composeChains(tc *TargetContext, res Ret2pltResolution) []ComposedChain {
	const goal = "spawn_shell"
	var chains []ComposedChain

	// 1) Direct ret2plt: overflow -> CONTROL, then CALL system/exec* with an
	//    in-binary string. No leak needed. The most direct chain when the binary
	//    has the material.
	ret2plt := ComposedChain{
		Goal: goal, Cost: CostCheap,
		Steps: []ChainStep{
			{Strategy: "stack_overflow", Produces: PrimitiveControl, Via: "overflow a saved return address", Satisfied: true},
			{Strategy: "ret2plt", Produces: PrimitiveCall, Via: ret2pltVia(res), Satisfied: res.Feasible()},
		},
		Feasible: res.Feasible(),
	}
	if res.Feasible() {
		ret2plt.Reason = "binary has pop-rdi, a system/exec PLT stub, and a command string"
	} else {
		ret2plt.Reason = "missing " + ret2pltMissing(res)
	}
	chains = append(chains, ret2plt)

	// 2) Cross-strategy: a format-string (or other) LEAK resolves libc, which
	//    ret2libc then consumes to CALL system("/bin/sh"). This is the composition
	//    single-strategy plans cannot express — the leak step feeds the chain step,
	//    and a leak already in Knowledge is reused rather than rediscovered.
	leakOK, leakWhy := libcLeakAvailable(tc)
	ret2libc := ComposedChain{
		Goal: goal, Cost: CostModerate,
		Steps: []ChainStep{
			{Strategy: "leak", Produces: PrimitiveLeak, Via: leakStepVia(leakOK, leakWhy), Satisfied: leakOK},
			{Strategy: "stack_overflow", Produces: PrimitiveControl, Via: "overflow a saved return address", Satisfied: true},
			{Strategy: "ret2libc", Produces: PrimitiveCall, Via: "pop rdi -> \"/bin/sh\"; system() in the leaked libc", Satisfied: res.HasPopRDI && leakOK},
		},
		Feasible: res.HasPopRDI && leakOK,
	}
	switch {
	case ret2libc.Feasible:
		ret2libc.Reason = "a libc leak is available (" + leakWhy + ") and pop-rdi is present; reuses the leak"
	case !res.HasPopRDI:
		ret2libc.Reason = "no pop-rdi gadget to load the argument register"
	default:
		ret2libc.Reason = "needs a libc leak first (none established yet)"
	}
	chains = append(chains, ret2libc)

	return chains
}

func ret2pltVia(res Ret2pltResolution) string {
	if res.Feasible() {
		return fmt.Sprintf("pop rdi @ %#x -> %q @ %#x -> %s@plt @ %#x",
			res.PopRDI, res.Strings[0].text, res.Strings[0].addr, res.Calls[0].name, res.Calls[0].addr)
	}
	return "pop rdi -> command string -> system/exec@plt"
}

func ret2pltMissing(res Ret2pltResolution) string {
	var m []string
	if !res.HasPopRDI {
		m = append(m, "pop-rdi gadget")
	}
	if len(res.Calls) == 0 {
		m = append(m, "system/exec PLT stub")
	}
	if len(res.Strings) == 0 {
		m = append(m, "command string")
	}
	return joinComma(m)
}

func leakStepVia(ok bool, why string) string {
	if ok {
		return why
	}
	return "establish a libc leak (e.g. a format-string read)"
}

func joinComma(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}
