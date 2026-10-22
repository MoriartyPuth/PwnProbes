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

// eligible returns the strategies that support mode, deterministically ranked,
// and the strategies rejected for that mode with their reasons. Ranking is: keep
// each mode's historical run order, then stably defer the expensive strategies
// (symbolic execution, cross-run brute force) behind all cheaper ones, so a
// strongly-supported cheap or moderate strategy is always tried before a costly
// speculative fallback. The sort is stable, so fixed inputs yield a fixed order.
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
	// Primary key: non-expensive before expensive. Secondary: mode order. A
	// stable sort preserves mode order within each cost group.
	sort.SliceStable(sel, func(i, j int) bool { return sel[i].order < sel[j].order })
	sort.SliceStable(sel, func(i, j int) bool {
		return !sel[i].st.Cost().Expensive && sel[j].st.Cost().Expensive
	})
	run := make([]Strategy, len(sel))
	for i, e := range sel {
		run[i] = e.st
	}
	return run, rejected
}
