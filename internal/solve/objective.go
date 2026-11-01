package solve

// This file holds the generalized objective/verification model (roadmap §19,
// §20). The solver's whole notion of success remains a single Solved bool
// meaning "a non-echoed flag was recovered"; that is kept, verbatim, as the
// authoritative signal. On top of it, a run is verified against a set of
// objectives (RecoverFlag plus EstablishLeak / DemonstrateControl /
// DemonstrateWrite / SpawnShell; see objectives.go), so a result stays
// meaningful short of a full solve and distinguishes observation, confirmation,
// primitive, and objective success. Grading is honest: a crash reaches only
// Observed, and an objective is met only on evidence that actually demonstrates
// it (an established primitive, or a solve via a technique of the right class).

// Outcome is what an objective inspects: a read-only projection of the finished
// run. It carries the recovered flags, whether the run solved, the winning
// strategy (so an objective can tell which capability a solve demonstrated), the
// established primitives, the findings, and the strongest status any finding
// reached. It is a projection of the finished report, not new state.
type Outcome struct {
	Flags             []string
	Solved            bool
	WinningStrategy   string
	ShellDemonstrated bool
	Primitives        []Primitive
	Findings          []Finding
	HighestStatus     VerificationStatus
}

// Verification is an objective's graded result: how far the run got toward that
// objective, with a human-readable reason and any flags that satisfied it.
type Verification struct {
	Objective string             `json:"objective"`
	Status    VerificationStatus `json:"status"`
	Detail    string             `json:"detail"`
	Flags     []string           `json:"flags,omitempty"`
}

// Objective is a goal a run can be verified against (roadmap §19). Verify is a
// pure mapping from an Outcome to a graded Verification; it never executes the
// target.
type Objective interface {
	ID() string
	Verify(Outcome) Verification
}

// RecoverFlag is the objective PwnProbes has always pursued: recover text
// matching the configured flag pattern, disclosed by the program and absent from
// the input. Its Verify reproduces the legacy meaning of Solved — flags present
// ⇒ objective met — while grading partial progress from the evidence otherwise.
type RecoverFlag struct{}

func (RecoverFlag) ID() string { return "recover_flag" }

// Verify grades the run: a recovered flag is ObjectiveMet; otherwise the result
// is the strongest status the evidence reached (a confirmed behavior, or a bare
// crash observation), and Inconclusive when nothing was established. This never
// promotes a crash to a solve — StatusObserved is as far as a crash alone goes.
func (o RecoverFlag) Verify(out Outcome) Verification {
	if len(out.Flags) > 0 {
		return Verification{
			Objective: o.ID(),
			Status:    StatusObjectiveMet,
			Detail:    "recovered a non-echoed flag matching the configured pattern",
			Flags:     out.Flags,
		}
	}
	switch out.HighestStatus {
	case StatusConfirmed:
		return Verification{Objective: o.ID(), Status: StatusConfirmed,
			Detail: "a reproducible input-dependent behavior was confirmed, but no flag was recovered"}
	case StatusObserved:
		return Verification{Objective: o.ID(), Status: StatusObserved,
			Detail: "an event was observed (e.g. a crash), but nothing was confirmed and no flag was recovered"}
	default:
		return Verification{Objective: o.ID(), Status: StatusInconclusive,
			Detail: "no flag recovered and no supporting evidence established"}
	}
}

// outcomeFrom projects a finished report and its shared context into an Outcome:
// the recovered flags (Solved stays authoritative), the winning strategy, the
// established primitives and findings, and the strongest finding status reached.
func outcomeFrom(report *Report, tc *TargetContext) Outcome {
	highest := StatusInconclusive
	var prims []Primitive
	var finds []Finding
	if tc != nil {
		for _, f := range tc.Findings {
			if StatusRank(f.Status) > StatusRank(highest) {
				highest = f.Status
			}
		}
		prims = tc.Primitives
		finds = tc.Findings
	}
	var flags []string
	var winning string
	var shell bool
	if report.Solved {
		flags = report.Flags
		if report.Winning != nil {
			winning = report.Winning.Strategy
			_, shell = demonstratedBy(winning)
		}
	}
	return Outcome{
		Flags:             flags,
		Solved:            report.Solved,
		WinningStrategy:   winning,
		ShellDemonstrated: shell,
		Primitives:        prims,
		Findings:          finds,
		HighestStatus:     highest,
	}
}
