package solve

import "testing"

// A confirmed format-string finding establishes exactly one controlled,
// repeatable stack LEAK, referencing that finding and claiming no more.
func TestEstablishPrimitivesFormatStringLeak(t *testing.T) {
	tc := &TargetContext{Target: Target{Bits: 64}}
	tc.addFinding(Finding{ID: "detect/format_string/0", Kind: FindingFormatString, Status: StatusConfirmed, Source: "detect"})
	tc.establishPrimitives()

	leaks := primitivesOfKind(tc, PrimitiveLeak)
	if len(leaks) != 1 {
		t.Fatalf("want 1 leak primitive, got %d (%+v)", len(leaks), tc.Primitives)
	}
	p := leaks[0]
	if p.Domain != DomainStack || !p.Controlled || !p.Repeatable {
		t.Errorf("format-string leak mischaracterized: %+v", p)
	}
	if p.Width != 8 {
		t.Errorf("width = %d, want 8 (64-bit pointer)", p.Width)
	}
	if p.Status != StatusPrimitiveEstablished {
		t.Errorf("status = %q, want primitive_established", p.Status)
	}
	if len(p.Evidence) != 1 || p.Evidence[0] != "detect/format_string/0" {
		t.Errorf("evidence must reference the finding, got %v", p.Evidence)
	}
	// No write or control is claimed from a %p leak alone.
	if len(primitivesOfKind(tc, PrimitiveWrite))+len(primitivesOfKind(tc, PrimitiveControl)) != 0 {
		t.Errorf("a format-string read must not establish write/control: %+v", tc.Primitives)
	}
}

// A crash is only an observation and must never establish any primitive.
func TestEstablishPrimitivesCrashEstablishesNothing(t *testing.T) {
	tc := &TargetContext{Target: Target{Bits: 64}}
	tc.addFinding(Finding{ID: "detect/crash/0", Kind: FindingCrash, Status: StatusObserved, Source: "detect"})
	tc.establishPrimitives()
	if len(tc.Primitives) != 0 {
		t.Errorf("a crash established %d primitive(s); want 0 (%+v)", len(tc.Primitives), tc.Primitives)
	}
}

// Disclosed runtime pointers become uncontrolled LEAK primitives per domain,
// each referencing a synthesized leak finding over the concrete values.
func TestEstablishPrimitivesDisclosedLeaks(t *testing.T) {
	tc := &TargetContext{Target: Target{Bits: 64}}
	tc.recordLeaks([]uint64{0x7ffff7a0d000, 0x555555556010}) // one stack-ish, one heap-ish
	tc.establishPrimitives()

	leaks := primitivesOfKind(tc, PrimitiveLeak)
	if len(leaks) != 2 {
		t.Fatalf("want 2 disclosed-leak primitives (stack+heap), got %d (%+v)", len(leaks), leaks)
	}
	var sawStack, sawHeap bool
	for _, p := range leaks {
		if p.Controlled {
			t.Errorf("a volunteered disclosure must not be marked controlled: %+v", p)
		}
		if len(p.Evidence) != 1 {
			t.Errorf("disclosed leak must reference a finding: %+v", p)
		}
		// The referenced finding must exist and be a leak finding.
		if findingByID(tc, p.Evidence[0]) == nil {
			t.Errorf("evidence %q has no matching finding", p.Evidence[0])
		}
		switch p.Domain {
		case DomainStack:
			sawStack = true
		case DomainHeap:
			sawHeap = true
		}
	}
	if !sawStack || !sawHeap {
		t.Errorf("want one stack and one heap leak primitive, got %+v", leaks)
	}
}

// 32-bit targets disclose 4-byte pointers.
func TestPointerWidth32(t *testing.T) {
	tc := &TargetContext{Target: Target{Bits: 32}}
	if tc.pointerWidth() != 4 {
		t.Errorf("pointerWidth() = %d, want 4 on a 32-bit target", tc.pointerWidth())
	}
}

// Primitive ids are unique within a run, so references are unambiguous.
func TestPrimitiveIDsUnique(t *testing.T) {
	tc := &TargetContext{Target: Target{Bits: 64}}
	tc.addFinding(Finding{ID: "detect/format_string/0", Kind: FindingFormatString, Status: StatusConfirmed, Source: "detect"})
	tc.recordLeaks([]uint64{0x7ffff7a0d000, 0x555555556010})
	tc.establishPrimitives()
	seen := map[string]bool{}
	for _, p := range tc.Primitives {
		if seen[p.ID] {
			t.Errorf("duplicate primitive id %q", p.ID)
		}
		seen[p.ID] = true
	}
	if len(tc.Primitives) != 3 {
		t.Fatalf("want 3 primitives (fmt + stack + heap), got %d", len(tc.Primitives))
	}
}

func primitivesOfKind(tc *TargetContext, k PrimitiveKind) []Primitive {
	var out []Primitive
	for _, p := range tc.Primitives {
		if p.Kind == k {
			out = append(out, p)
		}
	}
	return out
}

func findingByID(tc *TargetContext, id string) *Finding {
	for i := range tc.Findings {
		if tc.Findings[i].ID == id {
			return &tc.Findings[i]
		}
	}
	return nil
}
