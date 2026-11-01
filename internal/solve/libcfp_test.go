package solve

import "testing"

// resolveBaseFromLeaks fingerprints the base from a leak of any symbol (not just
// system), by matching the leak's page offset to a symbol's offset.
func TestResolveBaseFromLeaksAnySymbol(t *testing.T) {
	base := uint64(0x7f1234500000)
	syms := map[string]uint64{"system": 0x58750, "puts": 0x875a0, "printf": 0x614a0}
	// Leak puts (not system). The base must still resolve.
	leak := base + syms["puts"]
	got, ok := resolveBaseFromLeaks([]uint64{leak}, syms)
	if !ok || got != base {
		t.Fatalf("puts leak: base = %#x (ok=%v), want %#x", got, ok, base)
	}
}

// Two leaks from the same libc agree on one base, which outvotes any chance
// low-12-bit coincidence from an unrelated value.
func TestResolveBaseFromLeaksConsensus(t *testing.T) {
	base := uint64(0x7faa00000000)
	syms := map[string]uint64{"system": 0x58750, "puts": 0x875a0}
	leaks := []uint64{
		base + syms["system"],
		base + syms["puts"],
		0xdeadb000, // unrelated, page-aligned low bits, no symbol consensus
	}
	got, ok := resolveBaseFromLeaks(leaks, syms)
	if !ok || got != base {
		t.Fatalf("consensus base = %#x (ok=%v), want %#x", got, ok, base)
	}
}

// A system() leak still resolves (the pre-existing case is preserved).
func TestResolveBaseFromLeaksSystem(t *testing.T) {
	base := uint64(0x555500000000)
	syms := map[string]uint64{"system": 0x58750}
	if got, ok := resolveBaseFromLeaks([]uint64{base + 0x58750}, syms); !ok || got != base {
		t.Errorf("system leak: base = %#x (ok=%v), want %#x", got, ok, base)
	}
}

// No leak matching any symbol's page offset -> no base (prompts the --libc hint).
func TestResolveBaseFromLeaksNoMatch(t *testing.T) {
	syms := map[string]uint64{"system": 0x58750} // low 12 bits 0x750
	if _, ok := resolveBaseFromLeaks([]uint64{0x7f0000000111}, syms); ok {
		t.Error("a leak that matches no symbol's page offset should not resolve a base")
	}
}
