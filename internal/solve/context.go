package solve

import (
	"fmt"

	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
)

// TargetContext is the shared state for a solve run (roadmap §5). Before this,
// information was scattered across inspect.Report, detect.Report, solver fields,
// and transient locals inside each strategy. TargetContext centralizes it so a
// strategy records what it learns and later strategies reuse it instead of
// rediscovering it. Primitives (roadmap §7) are a later PR; the field is omitted
// here deliberately so this change stays additive and behavior-preserving.
type TargetContext struct {
	Target       Target         `json:"target"`
	Binary       inspect.Report `json:"binary"`
	Capabilities Capabilities   `json:"capabilities"`
	Findings     []Finding      `json:"findings"`
	Knowledge    Knowledge      `json:"knowledge"`
}

// Target is the identity of the thing under test, independent of any one
// analysis pass. It is what Knowledge and Findings are *about*, so a saved result
// can later be checked against the binary it was produced from.
type Target struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	Architecture string `json:"architecture"`
	Bits         int    `json:"bits"`
	Mode         string `json:"mode"` // "local" or "remote"
	Remote       string `json:"remote,omitempty"`
}

// Capabilities is a side-effect-free reading of the binary's mitigations, lifted
// out of the protections map so planning code can branch on booleans instead of
// re-parsing status strings. It states what is enabled, not how to defeat it.
type Capabilities struct {
	NX                 bool `json:"nx"`
	PIE                bool `json:"pie"`
	Canary             bool `json:"canary"`
	FullRELRO          bool `json:"full_relro"`
	ExecutionSupported bool `json:"execution_supported"`
}

// LibraryInfo records a resolved library and where its facts came from, so a
// reused address is traceable (roadmap §28.3: knowledge records its source). The
// offsets are file offsets within the library; a runtime base turns them into
// addresses.
type LibraryInfo struct {
	Path         string `json:"path"`
	Source       string `json:"source"` // how it was resolved: "ldd", "flag:--libc", ...
	SystemOffset uint64 `json:"system_offset,omitempty"`
	BinshOffset  uint64 `json:"binsh_offset,omitempty"`
	Resolved     bool   `json:"resolved"`
}

// Knowledge is the shared, reusable facts a run accumulates (roadmap §5): the
// identified libc, any recovered bases, and leaked stack/heap addresses. It lets
// strategies reuse what another already learned rather than rediscovering it. All
// fields are optional; a zero Knowledge means nothing has been learned yet.
type Knowledge struct {
	Libc       *LibraryInfo `json:"libc,omitempty"`
	PIEBase    *uint64      `json:"pie_base,omitempty"`
	LibcBase   *uint64      `json:"libc_base,omitempty"`
	StackLeaks []uint64     `json:"stack_leaks,omitempty"`
	HeapLeaks  []uint64     `json:"heap_leaks,omitempty"`
}

// newTargetContext builds the shared state from the static analysis. It reads
// identity and capabilities only; findings and knowledge fill in as the run
// proceeds.
func newTargetContext(bin inspect.Report, path, mode, remote string) *TargetContext {
	return &TargetContext{
		Target: Target{
			Path:         path,
			SHA256:       bin.SHA256,
			Architecture: bin.Architecture,
			Bits:         bin.Bits,
			Mode:         mode,
			Remote:       remote,
		},
		Binary:       bin,
		Capabilities: capabilitiesOf(bin),
		Findings:     []Finding{},
	}
}

// capabilitiesOf reads the protections map once into booleans. An absent or
// "unknown" protection is treated as not-established (false), which is the
// conservative reading for planning.
func capabilitiesOf(bin inspect.Report) Capabilities {
	on := func(name string) bool { return bin.Protections[name].Status == "enabled" }
	return Capabilities{
		NX:                 on("nx"),
		PIE:                on("pie"),
		Canary:             on("canary"),
		FullRELRO:          bin.Protections["relro"].Status == "full",
		ExecutionSupported: bin.ExecutionSupported,
	}
}

// addFinding appends a finding to the shared state.
func (tc *TargetContext) addFinding(f Finding) { tc.Findings = append(tc.Findings, f) }

// recordLeaks files observed pointer values into Knowledge, split by their
// address range, de-duplicating against what is already known. It is a pure
// recording step: it never changes control flow, so a strategy calling it stays
// behavior-preserving. Stack addresses cluster near the top of the canonical
// 48-bit user range; everything else is filed as a heap/other leak.
func (tc *TargetContext) recordLeaks(leaks []uint64) {
	for _, l := range leaks {
		if l >= 0x7f0000000000 {
			tc.Knowledge.StackLeaks = appendUnique(tc.Knowledge.StackLeaks, l)
		} else {
			tc.Knowledge.HeapLeaks = appendUnique(tc.Knowledge.HeapLeaks, l)
		}
	}
}

// appendUnique adds v to s only if absent, keeping the slice a set.
func appendUnique(s []uint64, v uint64) []uint64 {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// findingID builds a stable, readable id for a finding from its source, kind, and
// index, so findings can be referenced without a random component.
func findingID(source, kind string, i int) string {
	return fmt.Sprintf("%s/%s/%d", source, kind, i)
}
