package solve

import "testing"

func ids(sts []Strategy) []string {
	out := make([]string, len(sts))
	for i, s := range sts {
		out[i] = s.ID()
	}
	return out
}

func equalIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRegistryReproducesHistoricalOrder checks that the single registry yields
// exactly the former hand-maintained local and remote sequences, so unifying the
// two lists changed no behavior.
func TestRegistryReproducesHistoricalOrder(t *testing.T) {
	s := &solver{}
	reg := s.buildRegistry()

	wantLocal := []string{
		"fmt_got_overwrite", "fmt_write_ret", "heap_uaf", "stack_overwrite",
		"rop_ret2win_args", "rop_execve", "ret2plt", "shellcode", "ret2libc",
		"canary_ret2win", "angr_logic", "partial_overwrite", "rop_planner",
	}
	wantRemote := []string{
		"shellcode", "ret2libc", "rop_execve", "ret2plt", "canary_ret2win",
		"heap_uaf", "stack_overwrite_session", "partial_overwrite", "rop_planner",
	}

	gotLocal, _ := reg.eligible(ModeLocal)
	if got := ids(gotLocal); !equalIDs(got, wantLocal) {
		t.Fatalf("local order = %v, want %v", got, wantLocal)
	}
	gotRemote, _ := reg.eligible(ModeRemote)
	if got := ids(gotRemote); !equalIDs(got, wantRemote) {
		t.Fatalf("remote order = %v, want %v", got, wantRemote)
	}
}

// TestRegistryRejectionsExplained checks that strategies excluded for a mode are
// reported with a non-empty reason and never also appear in the run set.
func TestRegistryRejectionsExplained(t *testing.T) {
	s := &solver{}
	reg := s.buildRegistry()

	run, rejected := reg.eligible(ModeRemote)
	if len(rejected) == 0 {
		t.Fatal("expected some strategies rejected in remote mode (the local-only ones)")
	}
	runSet := map[string]bool{}
	for _, st := range run {
		runSet[st.ID()] = true
	}
	for _, rej := range rejected {
		if rej.Reason == "" {
			t.Fatalf("rejection for %q has no reason", rej.ID)
		}
		if runSet[rej.ID] {
			t.Fatalf("strategy %q is both run and rejected", rej.ID)
		}
	}
	// A known local-only strategy must be among the remote rejections.
	found := false
	for _, rej := range rejected {
		if rej.ID == "angr_logic" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected angr_logic to be rejected in remote mode")
	}
}

// TestSupportsIsConsistent checks Supports agrees with eligibility: every run
// strategy reports Supported, every rejected one reports not Supported.
func TestSupportsIsConsistent(t *testing.T) {
	s := &solver{}
	reg := s.buildRegistry()
	for _, mode := range []Mode{ModeLocal, ModeRemote} {
		run, rejected := reg.eligible(mode)
		for _, st := range run {
			if !st.Supports(mode).Supported {
				t.Fatalf("%q in run set but Supports(%s) is false", st.ID(), mode)
			}
		}
		for _, rej := range rejected {
			for _, st := range reg.all() {
				if st.ID() == rej.ID && st.Supports(mode).Supported {
					t.Fatalf("%q rejected but Supports(%s) is true", rej.ID, mode)
				}
			}
		}
	}
}
