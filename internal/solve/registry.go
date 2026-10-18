package solve

import "sort"

// Rejection is a strategy excluded for a mode, with the reason why. It makes the
// planner's selection explainable: a report can show what was not tried and why.
type Rejection struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// registry is the single catalog of strategies that both local and remote modes
// query, replacing the previously duplicated per-mode ordered lists. Each
// registered strategy declares, through Supports, which modes it applies to and
// (via its order) the sequence within a mode.
type registry struct {
	strategies []legacyStrategy
}

func newRegistry() *registry { return &registry{} }

// register adds a strategy to the catalog.
func (r *registry) register(st legacyStrategy) { r.strategies = append(r.strategies, st) }

// all returns every registered strategy in registration order.
func (r *registry) all() []legacyStrategy { return r.strategies }

// eligible returns the strategies that support mode, in ascending run order, and
// the strategies rejected for that mode with their reasons.
func (r *registry) eligible(mode Mode) ([]Strategy, []Rejection) {
	type ordered struct {
		st    legacyStrategy
		order int
	}
	var sel []ordered
	var rejected []Rejection
	for _, st := range r.strategies {
		if sup := st.Supports(mode); sup.Supported {
			o, _ := st.orderIn(mode)
			sel = append(sel, ordered{st, o})
		} else {
			rejected = append(rejected, Rejection{ID: st.ID(), Reason: sup.Reason})
		}
	}
	sort.SliceStable(sel, func(i, j int) bool { return sel[i].order < sel[j].order })
	run := make([]Strategy, len(sel))
	for i, e := range sel {
		run[i] = e.st
	}
	return run, rejected
}
