package solve

import "sort"

// This file wires the composer into execution (roadmap §30, follow-on). Until
// now composed chains were advisory — reported, but the engine still ran the
// registry's fixed deterministic order. applyComposition lets a composed chain
// actually drive selection: when a chain is feasible from a strong, static
// signal, its terminal strategy is promoted so the engine tries the technique
// its own reasoning endorsed first.
//
// It is deliberately conservative, to protect PR 6's ranking guarantees and the
// honest oracle:
//   - Only chains that are feasible AND cheap are allowed to promote. A cheap
//     chain's feasibility is a strong static fact (e.g. ret2plt: the binary has
//     the pop-rdi gadget, a system/exec PLT stub, and a command string), not the
//     coarse "a leak might be available" of the moderate chains, which stay
//     advisory.
//   - Promotion never moves a strategy ahead of the expensive/non-expensive split
//     PR 6 established: an endorsed strategy rises only within the non-expensive
//     group. Expensive strategies stay deferred.
//   - Nothing bypasses the oracle: a promoted strategy that does not actually
//     recover a flag simply yields to the next, exactly as before.

// SelectionNote records that a strategy's run order was changed, and why, so
// composition-driven selection is explainable.
type SelectionNote struct {
	Strategy string `json:"strategy"`
	Reason   string `json:"reason"`
}

// applyComposition reorders the eligible strategies so that the terminal
// strategies of feasible, cheap composed chains run first (within the
// non-expensive group), recording each promotion's rationale on the report. The
// sort is stable, so every non-promoted strategy keeps its deterministic rank.
func (s *solver) applyComposition(run []Strategy, chains []ComposedChain) []Strategy {
	endorse := map[string]string{} // strategy id -> chain reason
	for _, c := range chains {
		if !c.Feasible || c.Cost != CostCheap || len(c.Steps) == 0 {
			continue
		}
		term := c.Steps[len(c.Steps)-1].Strategy
		if _, seen := endorse[term]; !seen {
			endorse[term] = c.Reason
		}
	}
	if len(endorse) == 0 {
		return run
	}
	sort.SliceStable(run, func(i, j int) bool {
		ei, ej := run[i].Cost().Expensive, run[j].Cost().Expensive
		if ei != ej {
			return !ei // non-expensive first: preserve PR 6's expensive-deferred guarantee
		}
		_, pi := endorse[run[i].ID()]
		_, pj := endorse[run[j].ID()]
		return pi && !pj // within the same group, an endorsed strategy runs first
	})
	for _, st := range run {
		if reason, ok := endorse[st.ID()]; ok {
			s.report.Selection = append(s.report.Selection, SelectionNote{
				Strategy: st.ID(),
				Reason:   "composition-endorsed (" + reason + ")",
			})
		}
	}
	return run
}
