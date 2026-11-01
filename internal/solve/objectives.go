package solve

// This file generalizes verification beyond RecoverFlag (roadmap §19, §20).
// Each objective grades a run against its own goal using the verification
// ladder, so partial progress is reported honestly even when the full flag is
// not recovered. RecoverFlag (objective.go) stays authoritative for Solved; the
// objectives here are additive readings.
//
// The grading never overstates. An objective reaches ObjectiveMet only on
// evidence that actually demonstrates its goal: an established primitive
// (EstablishLeak), or a solve via a technique whose success demonstrates the
// capability (DemonstrateControl/Write/SpawnShell). Short of that it reports the
// strongest rung the evidence supports — a crash is only Observed — or
// Inconclusive when nothing bears on the goal.

// demonstratedBy reports the capabilities a *verified solve* via a strategy
// proves: the primitive kinds its success establishes, and whether that success
// spawned a shell. This is the single place the "which technique proves what"
// knowledge lives; it is consulted once, when a solve is recorded, to establish
// primitives (see establishDemonstratedCapabilities) — not re-derived at grading
// time. Entries are conservative: a strategy appears only where its success
// unambiguously implies the capability. Leak is established from evidence
// elsewhere, not here.
func demonstratedBy(strategy string) (kinds []PrimitiveKind, shell bool) {
	control := map[string]bool{
		"stack_overwrite": true, "stack_overwrite_session": true,
		"rop_ret2win_args": true, "rop_execve": true, "ret2plt": true,
		"rop_planner": true, "shellcode": true, "ret2libc": true,
		"canary_ret2win": true, "partial_overwrite": true, "heap_uaf": true,
		"fmt_got_overwrite": true, "fmt_write_ret": true,
	}
	write := map[string]bool{
		"stack_overwrite": true, "stack_overwrite_session": true,
		"fmt_got_overwrite": true, "fmt_write_ret": true,
	}
	call := map[string]bool{
		"rop_ret2win_args": true, "rop_execve": true, "ret2plt": true,
		"rop_planner": true, "ret2libc": true,
	}
	shellSet := map[string]bool{
		"rop_execve": true, "shellcode": true, "ret2libc": true,
		"stack_overwrite_session": true,
	}
	if control[strategy] {
		kinds = append(kinds, PrimitiveControl)
	}
	if write[strategy] {
		kinds = append(kinds, PrimitiveWrite)
	}
	if call[strategy] {
		kinds = append(kinds, PrimitiveCall)
	}
	return kinds, shellSet[strategy]
}

// hasPrimitiveKind reports whether the run established a primitive of kind k.
func (o Outcome) hasPrimitiveKind(k PrimitiveKind) bool {
	for _, p := range o.Primitives {
		if p.Kind == k {
			return true
		}
	}
	return false
}

// hasLeakPrimitive reports whether the run established any leak primitive.
func (o Outcome) hasLeakPrimitive() bool { return o.hasPrimitiveKind(PrimitiveLeak) }

// hasConfirmedFormatString reports whether a format-string behavior was confirmed.
func (o Outcome) hasConfirmedFormatString() bool {
	for _, f := range o.Findings {
		if f.Kind == FindingFormatString && f.Status == StatusConfirmed {
			return true
		}
	}
	return false
}

// observedCrash reports whether a crash was observed (the lowest ladder rung).
func (o Outcome) observedCrash() bool {
	for _, f := range o.Findings {
		if f.Kind == FindingCrash && f.Status == StatusObserved {
			return true
		}
	}
	return false
}

// EstablishLeak: can the run read memory / disclose an address? Met when a leak
// primitive was established; a confirmed format string is partial progress
// (Confirmed), since the read behavior is shown but no address is established yet.
type EstablishLeak struct{}

func (EstablishLeak) ID() string { return "establish_leak" }
func (o EstablishLeak) Verify(out Outcome) Verification {
	switch {
	case out.hasLeakPrimitive():
		return Verification{Objective: o.ID(), Status: StatusObjectiveMet,
			Detail: "a leak primitive was established"}
	case out.hasConfirmedFormatString():
		return Verification{Objective: o.ID(), Status: StatusConfirmed,
			Detail: "format-string read behavior confirmed; no address established yet"}
	default:
		return Verification{Objective: o.ID(), Status: StatusInconclusive,
			Detail: "no leak established"}
	}
}

// DemonstrateControl: was control of execution (a saved return address or a
// called function pointer) demonstrated? Met when the run solved via a
// control-flow technique; a bare observed crash is potential-but-unconfirmed
// control (Observed), never promoted further.
type DemonstrateControl struct{}

func (DemonstrateControl) ID() string { return "demonstrate_control" }
func (o DemonstrateControl) Verify(out Outcome) Verification {
	switch {
	case out.hasPrimitiveKind(PrimitiveControl):
		return Verification{Objective: o.ID(), Status: StatusObjectiveMet,
			Detail: "a control primitive was established (saved return address / function pointer)"}
	case out.observedCrash():
		return Verification{Objective: o.ID(), Status: StatusObserved,
			Detail: "a crash was observed; control is possible but unconfirmed"}
	default:
		return Verification{Objective: o.ID(), Status: StatusInconclusive,
			Detail: "no control demonstrated"}
	}
}

// DemonstrateWrite: was a memory write demonstrated? Met when the run solved via
// a technique whose success requires a write (an overflow, a format-string %n).
type DemonstrateWrite struct{}

func (DemonstrateWrite) ID() string { return "demonstrate_write" }
func (o DemonstrateWrite) Verify(out Outcome) Verification {
	if out.hasPrimitiveKind(PrimitiveWrite) {
		return Verification{Objective: o.ID(), Status: StatusObjectiveMet,
			Detail: "a write primitive was established"}
	}
	return Verification{Objective: o.ID(), Status: StatusInconclusive,
		Detail: "no write demonstrated"}
}

// SpawnShell: did the run spawn a shell? Met when it solved via a shell-spawning
// technique; otherwise inconclusive (a flag read without a shell does not count).
type SpawnShell struct{}

func (SpawnShell) ID() string { return "spawn_shell" }
func (o SpawnShell) Verify(out Outcome) Verification {
	// A spawned shell is a goal, not a memory primitive, so it reads the shell
	// flag the solve recorded (set once, from the same classification that
	// established the primitives) rather than re-inspecting strategy names.
	if out.ShellDemonstrated {
		return Verification{Objective: o.ID(), Status: StatusObjectiveMet,
			Detail: "solved via a shell-spawning technique (" + out.WinningStrategy + ")"}
	}
	return Verification{Objective: o.ID(), Status: StatusInconclusive,
		Detail: "no shell demonstrated"}
}

// CustomPredicate verifies a caller-supplied predicate over the outcome, so a
// researcher can define an ad-hoc objective (roadmap §19 CustomPredicate). It is
// not part of the standard set; it is constructed explicitly.
type CustomPredicate struct {
	Name string
	Pred func(Outcome) bool
}

func (c CustomPredicate) ID() string { return "custom:" + c.Name }
func (c CustomPredicate) Verify(out Outcome) Verification {
	if c.Pred != nil && c.Pred(out) {
		return Verification{Objective: c.ID(), Status: StatusObjectiveMet,
			Detail: "custom predicate satisfied"}
	}
	return Verification{Objective: c.ID(), Status: StatusInconclusive,
		Detail: "custom predicate not satisfied"}
}

// StandardObjectives is the set every run is verified against, RecoverFlag first
// so it remains the authoritative, compatibility-preserving objective.
func StandardObjectives() []Objective {
	return []Objective{
		RecoverFlag{},
		EstablishLeak{},
		DemonstrateControl{},
		DemonstrateWrite{},
		SpawnShell{},
	}
}

// EvaluateObjectives verifies the outcome against the given objectives (the
// standard set when none are supplied), returning one Verification each, in order.
func EvaluateObjectives(out Outcome, objs ...Objective) []Verification {
	if len(objs) == 0 {
		objs = StandardObjectives()
	}
	vs := make([]Verification, len(objs))
	for i, o := range objs {
		vs[i] = o.Verify(out)
	}
	return vs
}
