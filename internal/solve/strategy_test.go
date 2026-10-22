package solve

import (
	"context"
	"testing"
)

// TestCatalogIsCompleteAndDistinct checks the static catalog: every strategy has
// a non-empty id and description, ids are unique, and the catalog covers every
// strategy the solver actually runs (local, remote, and format-string).
func TestCatalogIsCompleteAndDistinct(t *testing.T) {
	cat := Catalog()
	if len(cat) == 0 {
		t.Fatal("catalog is empty")
	}

	ids := map[string]bool{}
	for _, st := range cat {
		if st.ID == "" {
			t.Fatalf("catalog entry with empty id: %+v", st)
		}
		if st.Description == "" {
			t.Fatalf("strategy %q has no description", st.ID)
		}
		if ids[st.ID] {
			t.Fatalf("duplicate strategy id in catalog: %q", st.ID)
		}
		ids[st.ID] = true
	}

	// Every strategy the solver would run must appear in the catalog, so the
	// listing never drifts from what executes.
	s := &solver{}
	var runnable []Strategy
	for _, st := range s.buildRegistry().all() {
		runnable = append(runnable, st)
	}
	runnable = append(runnable, s.formatStrategy())
	for _, st := range runnable {
		if !ids[st.ID()] {
			t.Fatalf("strategy %q runs but is missing from Catalog()", st.ID())
		}
		if st.Description() == "" {
			t.Fatalf("runnable strategy %q has no description", st.ID())
		}
	}

	// A couple of well-known ids should be present.
	for _, want := range []string{"ret2plt", "rop_planner", "format_string"} {
		if !ids[want] {
			t.Fatalf("expected strategy %q in catalog", want)
		}
	}
}

// TestLegacyStrategyWraps confirms the wrapper exposes identity and forwards Run.
func TestLegacyStrategyWraps(t *testing.T) {
	called := false
	st := newLegacy("demo", "a demo strategy", CostModerate, nil, func(context.Context) (bool, error) {
		called = true
		return true, nil
	})
	if st.ID() != "demo" || st.Description() != "a demo strategy" {
		t.Fatalf("id/desc = %q/%q, want demo/a demo strategy", st.ID(), st.Description())
	}
	done, err := st.Run(context.Background())
	if err != nil || !done {
		t.Fatalf("Run returned done=%v err=%v, want true/nil", done, err)
	}
	if !called {
		t.Fatal("Run did not invoke the wrapped function")
	}
}
