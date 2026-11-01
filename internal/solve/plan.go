package solve

import "fmt"

// This file separates planning from execution (roadmap §8, §10). A Plan is an
// inspectable description of how a strategy would try to reach the objective —
// its steps, cost, risk, the primitives it would produce, and whether its static
// preconditions hold — produced WITHOUT executing the target. The same plan
// object is what a human inspects, auto mode executes, and (later) assisted mode
// approves.
//
// This PR does not rewrite the solvers: their Run methods remain the execution
// path. Selected deterministic strategies additionally describe their plan via a
// planFn; the session/symbolic/heap strategies remain execution-only and expose
// no plan (canPlan() == false), which is stated explicitly in the catalog.
// Planning reads only static analysis (TargetContext and the ELF), so it never
// runs the target — `pwnprobe solve --plan-only` yields plans with no attempts.

// RiskLevel is a coarse, static read of how likely a plan is to mislead or to
// burn budget. It is derived from the strategy's cost tier, not from a claim
// about the target.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// Requirement is a single precondition of a plan and whether it is met. Only
// statically decidable preconditions are recorded here; runtime facts a plan
// assumes (e.g. a reachable overflow) are stated in the steps and verified during
// execution, never asserted as met in advance.
type Requirement struct {
	Name   string `json:"name"`
	Met    bool   `json:"met"`
	Detail string `json:"detail,omitempty"`
}

// Step is one ordered action in a plan, phrased for a human to read.
type Step struct {
	Index  int    `json:"index"`
	Action string `json:"action"`
}

// Plan is an inspectable description of a strategy's intended approach, produced
// without executing the target. Feasible is true when every (statically
// decidable) Requirement is met; an infeasible plan is still produced, with the
// unmet requirement visible, so a researcher sees why a strategy would be
// skipped rather than having it silently spend attempts.
type Plan struct {
	ID       string          `json:"id"`
	Strategy string          `json:"strategy"`
	Steps    []Step          `json:"steps"`
	Cost     CostEstimate    `json:"cost"`
	Risk     RiskLevel       `json:"risk"`
	Requires []Requirement   `json:"requires"`
	Produces []PrimitiveKind `json:"produces,omitempty"`
	Feasible bool            `json:"feasible"`
	Note     string          `json:"note,omitempty"`
}

// Planner is the contract a strategy's planFn conforms to: describe the plan for
// a target without executing it. Strategies that have not been split into
// plan/execute do not provide one and remain execution-only.
type Planner interface {
	Plan(*TargetContext) Plan
}

// planIfAble returns the strategy's plan when it has a planFn, else ok=false.
// Execution-only strategies return ok=false here, which is how the orchestrator
// keeps them explicit.
func (l legacyStrategy) planIfAble(tc *TargetContext) (Plan, bool) {
	if l.planFn == nil {
		return Plan{}, false
	}
	return l.planFn(tc), true
}

// canPlan reports whether the strategy can describe a plan (vs. execution-only).
func (l legacyStrategy) canPlan() bool { return l.planFn != nil }

// collectPlans returns the plans of the plannable strategies eligible for mode,
// in ranked order, each finalized with the strategy's cost and derived risk. It
// executes nothing: it only queries each strategy's planFn against the shared
// context.
func (s *solver) collectPlans(mode Mode, reg *registry) []Plan {
	run, _ := reg.eligible(mode)
	var plans []Plan
	for _, st := range run {
		ls, ok := st.(legacyStrategy)
		if !ok {
			continue
		}
		p, able := ls.planIfAble(s.tc)
		if !able {
			continue
		}
		p.ID = ls.ID()
		p.Strategy = ls.ID()
		p.Cost = ls.Cost()
		p.Risk = riskFromCost(p.Cost.Tier)
		plans = append(plans, p)
	}
	return plans
}

// riskFromCost maps a static cost tier to a coarse risk level.
func riskFromCost(t CostTier) RiskLevel {
	switch t {
	case CostCheap:
		return RiskLow
	case CostExpensive:
		return RiskHigh
	default:
		return RiskMedium
	}
}

// --- plan helpers -----------------------------------------------------------

func steps(actions ...string) []Step {
	out := make([]Step, len(actions))
	for i, a := range actions {
		out[i] = Step{Index: i + 1, Action: a}
	}
	return out
}

func planFeasible(rs []Requirement) bool {
	for _, r := range rs {
		if !r.Met {
			return false
		}
	}
	return true
}

// reqAmd64 / reqNoPIE / reqNX are the common static preconditions, phrased once.
func reqAmd64(tc *TargetContext) Requirement {
	return Requirement{Name: "64-bit x86-64 target", Met: tc.Target.Bits == 64}
}

func reqNoPIE(tc *TargetContext) Requirement {
	met := !tc.Capabilities.PIE
	detail := ""
	if !met {
		detail = "PIE enabled; addresses are not fixed without a leak"
	}
	return Requirement{Name: "non-PIE (fixed addresses)", Met: met, Detail: detail}
}

// hasWinFunction reports whether the binary defines a win-named function (win,
// flag, shell, ...), the natural target of a ret2win redirect.
func hasWinFunction(tc *TargetContext) bool {
	for _, fn := range orderedWinFunctions(tc.Binary) {
		if winNameRe.MatchString(fn.name) {
			return true
		}
	}
	return false
}

// --- per-strategy plans (selected deterministic strategies) -----------------

func planStackOverwrite(tc *TargetContext) Plan {
	reqs := []Requirement{
		{Name: "target is executable here", Met: tc.Capabilities.ExecutionSupported},
	}
	return Plan{
		Steps: steps(
			"recognize a win function or a guard variable + magic constant from static analysis",
			"brute-force the padding to the saved return address (one-shot runs)",
			"overwrite the saved return address with the win function, or set the guard variable",
			"verify the objective (non-echoed flag disclosed)",
		),
		Requires: reqs,
		Produces: []PrimitiveKind{PrimitiveControl},
		Feasible: planFeasible(reqs),
		Note:     "two shapes: ret2win (control saved RIP) or guard-variable overwrite",
	}
}

func planRopRet2winArgs(tc *TargetContext) Plan {
	reqs := []Requirement{
		reqAmd64(tc),
		reqNoPIE(tc),
		{Name: "win function present", Met: hasWinFunction(tc)},
	}
	return Plan{
		Steps: steps(
			"locate a win function that takes arguments",
			"find `pop rdi; ret` and `pop rsi; ret` gadgets",
			"establish the saved-RIP offset by padding",
			"build chain: padding -> pop rdi -> arg1 -> pop rsi -> arg2 -> win",
			"verify the objective",
		),
		Requires: reqs,
		Produces: []PrimitiveKind{PrimitiveControl, PrimitiveCall},
		Feasible: planFeasible(reqs),
	}
}

func planRopExecve(tc *TargetContext) Plan {
	reqs := []Requirement{
		reqAmd64(tc),
		reqNoPIE(tc),
	}
	return Plan{
		Steps: steps(
			"find a `syscall` gadget and pop gadgets for rax/rdi/rsi/rdx",
			"stage \"/bin/sh\" in writable memory or locate it",
			"build an execve(\"/bin/sh\", 0, 0) syscall chain",
			"drive the spawned shell to disclose the flag",
			"verify the objective",
		),
		Requires: reqs,
		Produces: []PrimitiveKind{PrimitiveControl, PrimitiveCall},
		Feasible: planFeasible(reqs),
	}
}

func planRet2plt(tc *TargetContext) Plan {
	return planRet2pltWith(tc, resolveRet2plt(tc))
}

// planRet2pltWith builds the ret2plt plan from an already-resolved view, so the
// plan's requirements and steps carry the concrete gadget, string, and PLT-stub
// addresses that execution will use. Separated from the ELF read so it can be
// unit-tested with a hand-built resolution.
func planRet2pltWith(tc *TargetContext, res Ret2pltResolution) Plan {
	reqs := []Requirement{
		reqAmd64(tc),
		reqNoPIE(tc),
		{Name: "pop rdi; ret gadget", Met: res.HasPopRDI,
			Detail: must(res.HasPopRDI, "at "+hexAddr(res.PopRDI, res.HasPopRDI), "no `pop rdi; ret` gadget found")},
		{Name: "callable system/exec* PLT stub", Met: len(res.Calls) > 0,
			Detail: must(len(res.Calls) > 0, callDetail(res.Calls), "no system/exec PLT stub resolved")},
		{Name: "in-binary command string", Met: len(res.Strings) > 0,
			Detail: must(len(res.Strings) > 0, stringDetail(res.Strings), "no usable command string in the binary")},
	}
	// Steps reference the concrete resolved addresses when present.
	argStep := "point rdi at an in-binary command string"
	if len(res.Strings) > 0 {
		argStep = fmt.Sprintf("point rdi at %q @ %#x", res.Strings[0].text, res.Strings[0].addr)
	}
	callStep := "call system/exec* through its PLT stub"
	if len(res.Calls) > 0 {
		callStep = fmt.Sprintf("return into %s@plt @ %#x", res.Calls[0].name, res.Calls[0].addr)
	}
	return Plan{
		Steps: steps(
			"establish the saved-RIP offset",
			fmt.Sprintf("load rdi via `pop rdi; ret` @ %s", hexAddr(res.PopRDI, res.HasPopRDI)),
			argStep,
			callStep,
			"verify the objective",
		),
		Requires: reqs,
		Produces: []PrimitiveKind{PrimitiveCall},
		Feasible: planFeasible(reqs),
	}
}

// callDetail / stringDetail summarize the resolved artifacts for a plan.
func callDetail(calls []pltCall) string {
	if len(calls) == 0 {
		return ""
	}
	return fmt.Sprintf("%s@plt at %#x", calls[0].name, calls[0].addr)
}

func stringDetail(strs []strEntry) string {
	if len(strs) == 0 {
		return ""
	}
	return fmt.Sprintf("%q at %#x", strs[0].text, strs[0].addr)
}

func planRopPlanner(tc *TargetContext) Plan {
	reqs := []Requirement{
		reqAmd64(tc),
		reqNoPIE(tc),
	}
	return Plan{
		Steps: steps(
			"harvest gadgets (pop sequences, ret, syscall) and constant immediates",
			"solve the register assignment for the target call group",
			"assemble multi-argument and chained calls",
			"verify the objective",
		),
		Requires: reqs,
		Produces: []PrimitiveKind{PrimitiveCall},
		Feasible: planFeasible(reqs),
	}
}

func planPartialOverwrite(tc *TargetContext) Plan {
	reqs := []Requirement{
		reqAmd64(tc),
		{Name: "PIE without a leak", Met: tc.Capabilities.PIE,
			Detail: must(tc.Capabilities.PIE, "", "partial overwrite applies to PIE targets with no leak")},
	}
	return Plan{
		Steps: steps(
			"identify a read-style overflow that does not append a terminator",
			"overwrite only the low 1-2 bytes of the saved return address",
			"retry across fresh runs until the randomized nibble aligns (~1 in 16)",
			"verify the objective",
		),
		Requires: reqs,
		Produces: []PrimitiveKind{PrimitiveControl},
		Feasible: planFeasible(reqs),
		Note:     "probabilistic: the un-leaked ASLR nibble must align",
	}
}

// must returns yes when cond, else no — a tiny helper for conditional detail text.
func must(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

// planSummary renders a one-line human summary of a plan.
func planSummary(p Plan) string {
	state := "feasible"
	if !p.Feasible {
		state = "infeasible"
	}
	return fmt.Sprintf("%s [%s, risk=%s, %d steps]", p.Strategy, state, p.Risk, len(p.Steps))
}
