package solve

// This file makes primitives first-class (roadmap §7). A vulnerability is not
// what a planner reasons about; the *capability* it grants is. A primitive
// records that capability explicitly — what kind, in which address domain, how
// wide, whether it repeats, and under what constraints — together with a
// reference to the evidence that established it. The guiding rule is the same one
// the evidence layer follows: never overstate. A primitive is established only
// from evidence that actually demonstrates it (a confirmed finding, a disclosed
// value), never from a bare crash or a plausible-looking payload. Composing
// primitives toward a goal is the planner's job in a later PR; this PR only names
// them honestly.

// PrimitiveKind is the capability a primitive represents.
type PrimitiveKind string

const (
	PrimitiveLeak    PrimitiveKind = "leak"    // read memory / disclose an address
	PrimitiveWrite   PrimitiveKind = "write"   // write memory
	PrimitiveControl PrimitiveKind = "control" // control a saved return address / function pointer
	PrimitiveCall    PrimitiveKind = "call"    // call a chosen function with chosen arguments
	PrimitiveAlloc   PrimitiveKind = "alloc"   // cause an allocation
	PrimitiveFree    PrimitiveKind = "free"    // cause a free
)

// AddressDomain names the region an address belongs to. It is the "where" a leak
// reads from or a write targets. Unknown is the honest default when the region
// has not been established.
type AddressDomain string

const (
	DomainStack   AddressDomain = "stack"
	DomainHeap    AddressDomain = "heap"
	DomainLibc    AddressDomain = "libc"
	DomainBinary  AddressDomain = "binary"
	DomainUnknown AddressDomain = "unknown"
)

// AddressConstraint describes where a write primitive can land. Arbitrary is set
// only when a write has actually been shown to reach any address; otherwise the
// Domain (and Note) bound it. This keeps "arbitrary write" from being claimed on
// the strength of a single constrained write.
type AddressConstraint struct {
	Domain    AddressDomain `json:"domain"`
	Arbitrary bool          `json:"arbitrary"`
	Note      string        `json:"note,omitempty"`
}

// Primitive is one established capability. The typed sub-fields are populated per
// Kind (Domain for a leak's source; Destination for a write's target; Target for
// what a control/call primitive drives); unused fields stay zero. Width is in
// bytes (0 = unspecified). Evidence lists the Finding IDs that establish it, so
// every primitive is traceable to what was observed; Status says how firmly it is
// established, never promoted beyond its evidence.
type Primitive struct {
	ID     string             `json:"id"`
	Kind   PrimitiveKind      `json:"kind"`
	Status VerificationStatus `json:"status"`
	Source string             `json:"source"`

	// Leak: Domain is the source region; Controlled is whether the read location
	// is attacker-selected (a %N$p position) rather than volunteered by the program.
	Domain     AddressDomain `json:"domain,omitempty"`
	Controlled bool          `json:"controlled,omitempty"`

	// Write: where it can land.
	Destination *AddressConstraint `json:"destination,omitempty"`

	// Control/Call: what is driven (e.g. "saved return address"); Partial marks a
	// control primitive that only reaches part of the target (a 1–2 byte overwrite).
	Target  string `json:"target,omitempty"`
	Partial bool   `json:"partial,omitempty"`

	Width      int      `json:"width,omitempty"`
	Repeatable bool     `json:"repeatable"`
	Evidence   []string `json:"evidence,omitempty"`
	Note       string   `json:"note,omitempty"`
}

// addPrimitive appends an established primitive to the shared state.
func (tc *TargetContext) addPrimitive(p Primitive) { tc.Primitives = append(tc.Primitives, p) }

// pointerWidth is the natural pointer width in bytes for the target, used as a
// leak/read width when a strategy discloses pointer-sized values.
func (tc *TargetContext) pointerWidth() int {
	if tc.Target.Bits == 32 {
		return 4
	}
	return 8
}

// establishPrimitives derives primitives from what the run actually demonstrated,
// conservatively. It runs once at the end of a solve, reading only established
// findings and disclosed knowledge — never a crash, never a mere attempt — so a
// primitive is present exactly when there is evidence for it:
//
//   - a confirmed format-string finding establishes a controlled, repeatable
//     LEAK in the stack domain (input-selected %p reads), evidenced by that
//     finding;
//   - pointer values the target disclosed at run time (recorded in Knowledge)
//     establish a LEAK in each domain they fell into — not marked controlled,
//     since the program volunteered them — evidenced by a synthesized leak
//     finding over the concrete values.
//
// It is idempotent per run (called once) and adds nothing when there is no
// supporting evidence, which is the point: no evidence, no primitive.
func (tc *TargetContext) establishPrimitives() {
	for _, f := range tc.Findings {
		if f.Kind == FindingFormatString && f.Status == StatusConfirmed {
			tc.addPrimitive(Primitive{
				ID:         primitiveID(tc, PrimitiveLeak),
				Kind:       PrimitiveLeak,
				Status:     StatusPrimitiveEstablished,
				Source:     f.Source,
				Domain:     DomainStack,
				Controlled: true,
				Width:      tc.pointerWidth(),
				Repeatable: true,
				Evidence:   []string{f.ID},
				Note:       "input-selected format-string read of the stack",
			})
		}
	}
	tc.establishDisclosedLeaks()
}

// establishDisclosedLeaks turns pointer values the target disclosed at run time
// (filed in Knowledge by recordLeaks) into a LEAK primitive per non-empty domain.
// The read location was not shown to be attacker-controlled, so Controlled is
// false and the capability is not overstated. Each primitive references a leak
// finding synthesized over the concrete values, so it is traceable.
func (tc *TargetContext) establishDisclosedLeaks() {
	add := func(domain AddressDomain, values []uint64) {
		if len(values) == 0 {
			return
		}
		fid := findingID("knowledge", "leak_"+string(domain), len(tc.Findings))
		tc.addFinding(Finding{
			ID:         fid,
			Kind:       FindingLeak,
			Status:     StatusConfirmed,
			Confidence: 1.0,
			Source:     "knowledge",
			Evidence:   []Observation{{Type: "disclosed_" + string(domain) + "_addresses", Value: values}},
		})
		tc.addPrimitive(Primitive{
			ID:         primitiveID(tc, PrimitiveLeak),
			Kind:       PrimitiveLeak,
			Status:     StatusPrimitiveEstablished,
			Source:     "knowledge",
			Domain:     domain,
			Controlled: false,
			Width:      tc.pointerWidth(),
			Repeatable: false,
			Evidence:   []string{fid},
			Note:       "address disclosed by the target at run time",
		})
	}
	add(DomainStack, tc.Knowledge.StackLeaks)
	add(DomainHeap, tc.Knowledge.HeapLeaks)
}

// primitiveID builds a stable id for a primitive from its kind and position.
func primitiveID(tc *TargetContext, kind PrimitiveKind) string {
	return findingID("primitive", string(kind), len(tc.Primitives))
}
