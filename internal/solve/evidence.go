package solve

import (
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/detect"
)

// This file makes evidence first-class (roadmap §6) without changing how the
// detector works. A Finding separates what was *observed* (an Observation: a
// signal, a byte count, a transcript match) from what it *means* (a FindingKind
// and a VerificationStatus). The rule the detector already follows is preserved
// here: a crash is only ever an observation, never "buffer overflow confirmed".

// FindingKind names the class of thing a finding is about. It describes the
// observation's subject, not a conclusion about exploitability — that lives in
// the finding's VerificationStatus.
type FindingKind string

const (
	FindingCrash        FindingKind = "crash"
	FindingFormatString FindingKind = "format_string"
	FindingLeak         FindingKind = "leak"
	FindingFlag         FindingKind = "flag"
)

// VerificationStatus is the generalized verification ladder (roadmap §20). It
// begins the move away from a single Solved bool toward graded outcomes, so a
// result is meaningful even when the full objective is not automated. The ladder
// is ordered by StatusRank; Inconclusive and Unsupported sit outside the ladder
// (rank 0) because they are terminal non-progress states, not rungs.
type VerificationStatus string

const (
	// StatusObserved: a raw event was seen (a signal, some output). It carries no
	// claim about cause or control — a SIGSEGV is Observed, nothing more.
	StatusObserved VerificationStatus = "observed"
	// StatusConfirmed: a reproducible, input-dependent behavior is established
	// (e.g. markers prove input-controlled %p expansion).
	StatusConfirmed VerificationStatus = "confirmed"
	// StatusPrimitiveEstablished: a usable capability (leak/write/control) is
	// demonstrated. Reserved for PR 8's explicit primitive models; defined here so
	// the ladder is complete.
	StatusPrimitiveEstablished VerificationStatus = "primitive_established"
	// StatusExploitabilityEstablished: a controlled call/redirect was reached but
	// the objective was not yet met.
	StatusExploitabilityEstablished VerificationStatus = "exploitability_established"
	// StatusObjectiveMet: the objective's own evidence test passed (e.g. a
	// non-echoed flag was recovered).
	StatusObjectiveMet VerificationStatus = "objective_met"

	// StatusInconclusive: a check ran but established nothing. Off-ladder.
	StatusInconclusive VerificationStatus = "inconclusive"
	// StatusUnsupported: the check does not apply to this target. Off-ladder.
	StatusUnsupported VerificationStatus = "unsupported"
)

// StatusRank orders the ladder so the strongest status reached can be reported.
// Off-ladder statuses rank 0. A higher rank is a stronger result.
func StatusRank(s VerificationStatus) int {
	switch s {
	case StatusObserved:
		return 1
	case StatusConfirmed:
		return 2
	case StatusPrimitiveEstablished:
		return 3
	case StatusExploitabilityEstablished:
		return 4
	case StatusObjectiveMet:
		return 5
	default:
		return 0
	}
}

// Observation is a single recorded fact: what was seen, when, and during which
// attempt. Value holds the raw datum (a signal string, a length, a matched
// substring); it is deliberately untyped so an observation can carry whatever the
// source saw without forcing an interpretation.
type Observation struct {
	Type      string    `json:"type"`
	Value     any       `json:"value,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	AttemptID string    `json:"attempt_id,omitempty"`
}

// Finding is a piece of evidence with provenance. Kind and Evidence record what
// was observed; Status and Confidence record how far it has been verified;
// Interpretation, when present, is an explicit, hedged reading that must never
// overstate the evidence (e.g. a crash finding leaves Interpretation empty rather
// than asserting control). Source names the module that produced it.
type Finding struct {
	ID             string             `json:"id"`
	Kind           FindingKind        `json:"kind"`
	Status         VerificationStatus `json:"status"`
	Confidence     float64            `json:"confidence"`
	Source         string             `json:"source"`
	Evidence       []Observation      `json:"evidence,omitempty"`
	Interpretation string             `json:"interpretation,omitempty"`
}

// translateDetection projects the detector's report into first-class findings
// without changing the detector. It is the single place the honest
// observation/interpretation split is re-expressed in the richer model:
//
//   - a "crash" detector finding becomes a FindingCrash at StatusObserved with
//     the signal as an observation and no interpretation — never an overflow
//     claim;
//   - a confirmed "format_string" finding becomes a FindingFormatString at
//     StatusConfirmed (a reproducible, input-dependent behavior).
//
// Any other detector finding is carried through as Observed so nothing is lost.
func translateDetection(d detect.Report, at time.Time) []Finding {
	var out []Finding
	for i, f := range d.Findings {
		switch {
		case f.Kind == "format_string" && f.Status == "confirmed_behavior":
			out = append(out, Finding{
				ID:         findingID("detect", "format_string", i),
				Kind:       FindingFormatString,
				Status:     StatusConfirmed,
				Confidence: 1.0,
				Source:     "detect",
				Evidence: []Observation{{
					Type:      "reproducible_expansion",
					Value:     f.Evidence,
					Timestamp: at,
				}},
			})
		case f.Kind == "crash":
			// A crash is only ever Observed. Cause and control are unconfirmed, so
			// Interpretation stays empty — preserving the detector's honesty.
			out = append(out, Finding{
				ID:         findingID("detect", "crash", i),
				Kind:       FindingCrash,
				Status:     StatusObserved,
				Confidence: 1.0,
				Source:     "detect",
				Evidence: []Observation{{
					Type:      "signal",
					Value:     f.Evidence,
					Timestamp: at,
				}},
			})
		default:
			out = append(out, Finding{
				ID:         findingID("detect", string(f.Kind), i),
				Kind:       FindingKind(f.Kind),
				Status:     StatusObserved,
				Confidence: 0,
				Source:     "detect",
				Evidence:   []Observation{{Type: "evidence", Value: f.Evidence, Timestamp: at}},
			})
		}
	}
	return out
}
