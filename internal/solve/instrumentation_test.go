package solve

import (
	"context"
	"testing"
)

// TestRunStrategyRecordsTiming checks that each strategy invocation appends a
// timing entry in order, with the number of attempts that strategy added.
func TestRunStrategyRecordsTiming(t *testing.T) {
	rep := &Report{}
	s := &solver{report: rep}

	done, err := s.runStrategy(context.Background(), "alpha", func(context.Context) (bool, error) {
		s.report.Attempts = append(s.report.Attempts, Attempt{Strategy: "a1"})
		return false, nil
	})
	if err != nil {
		t.Fatalf("alpha returned error: %v", err)
	}
	if done {
		t.Fatal("alpha should not have solved")
	}

	done, err = s.runStrategy(context.Background(), "beta", func(context.Context) (bool, error) {
		s.report.Attempts = append(s.report.Attempts, Attempt{Strategy: "b1"}, Attempt{Strategy: "b2"})
		return true, nil
	})
	if err != nil {
		t.Fatalf("beta returned error: %v", err)
	}
	if !done {
		t.Fatal("beta should have solved")
	}

	ts := rep.Timing.Strategies
	if len(ts) != 2 {
		t.Fatalf("got %d timing entries, want 2", len(ts))
	}
	if ts[0].Name != "alpha" || ts[0].Attempts != 1 {
		t.Fatalf("entry 0 = %+v, want alpha/1 attempt", ts[0])
	}
	if ts[1].Name != "beta" || ts[1].Attempts != 2 {
		t.Fatalf("entry 1 = %+v, want beta/2 attempts", ts[1])
	}
	for _, e := range ts {
		if e.DurationMS < 0 {
			t.Fatalf("entry %q has negative duration %d", e.Name, e.DurationMS)
		}
	}
}

// TestRunStrategiesStopsAtFirstSolve confirms the loop stops once a strategy
// solves and does not run later entries.
func TestRunStrategiesStopsAtFirstSolve(t *testing.T) {
	rep := &Report{}
	s := &solver{report: rep}
	ran := []string{}
	entries := []strategyEntry{
		{"one", func(context.Context) (bool, error) { ran = append(ran, "one"); return false, nil }},
		{"two", func(context.Context) (bool, error) { ran = append(ran, "two"); return true, nil }},
		{"three", func(context.Context) (bool, error) { ran = append(ran, "three"); return false, nil }},
	}
	if _, err := s.runStrategies(context.Background(), entries); err != nil {
		t.Fatalf("runStrategies error: %v", err)
	}
	if len(ran) != 2 || ran[0] != "one" || ran[1] != "two" {
		t.Fatalf("ran %v, want [one two] (three must not run after a solve)", ran)
	}
	if len(rep.Timing.Strategies) != 2 {
		t.Fatalf("recorded %d timing entries, want 2", len(rep.Timing.Strategies))
	}
}

// TestBuildCommitEnvOverride verifies the PWNPROBE_COMMIT override is used when
// VCS stamping is unavailable, so a report never carries a fabricated revision.
func TestBuildCommitEnvOverride(t *testing.T) {
	t.Setenv("PWNPROBE_COMMIT", "deadbeefcafe")
	if got := buildCommit(); got != "deadbeefcafe" {
		t.Fatalf("buildCommit() = %q, want the override value", got)
	}
}
