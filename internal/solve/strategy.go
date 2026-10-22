package solve

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Mode is an execution backend a strategy can target. Local is a subprocess;
// remote is a TCP service. It is the coarse capability dimension that the two
// former orchestration lists encoded by hand.
type Mode string

const (
	ModeLocal  Mode = "local"
	ModeRemote Mode = "remote"
)

// SupportResult answers whether a strategy is worth trying, with a reason when
// it is not. It is produced without touching the target (side-effect free), so
// the planner can explain selection before anything runs.
type SupportResult struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
}

// CostTier is a coarse, static estimate of how expensive a strategy is to try.
// It drives deterministic ranking: expensive strategies (symbolic execution,
// cross-run brute force) are deferred behind cheaper, targeted ones so they
// cannot starve the budget before a likely solver runs.
type CostTier string

const (
	CostCheap     CostTier = "cheap"     // deterministic, few attempts
	CostModerate  CostTier = "moderate"  // bounded brute force or a live session
	CostExpensive CostTier = "expensive" // symbolic execution or cross-run retries
)

// CostEstimate is a strategy's static cost. Expensive mirrors Tier == expensive
// and is the signal the planner ranks on; richer estimates (time, attempts) can
// be added once a reproduced baseline justifies the numbers.
type CostEstimate struct {
	Tier      CostTier `json:"tier"`
	Expensive bool     `json:"expensive"`
}

// Strategy is the common shape every exploitation technique exposes to the
// orchestrator. It carries identity, a side-effect-free Supports check, and
// legacy execution (Run still couples recognition, payload construction,
// execution, and verification; a Plan/Execute split comes later). Until then a
// strategy stays legacy execution-only.
type Strategy interface {
	ID() string
	Description() string
	// Supports reports whether the strategy applies to the given mode, without
	// running the target.
	Supports(mode Mode) SupportResult
	// Cost is the static cost estimate used for deterministic ranking.
	Cost() CostEstimate
	Run(ctx context.Context) (bool, error)
}

// StrategyInfo is a strategy's static identity, independent of any target. It
// backs `pwnprobe strategies`.
type StrategyInfo struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Modes       []Mode   `json:"modes"`
	Cost        CostTier `json:"cost"`
}

// legacyStrategy adapts an existing *solver method to the Strategy interface
// without changing its behavior. modes maps each supported mode to its run
// order within that mode (lower runs first); a mode absent from the map is
// unsupported. A nil modes map means "supported in any mode" and is used only
// by tests and the format-string strategy's local gating.
type legacyStrategy struct {
	id    string
	desc  string
	cost  CostTier
	modes map[Mode]int
	run   func(context.Context) (bool, error)
}

func (l legacyStrategy) ID() string          { return l.id }
func (l legacyStrategy) Description() string { return l.desc }
func (l legacyStrategy) Run(ctx context.Context) (bool, error) {
	return l.run(ctx)
}

// Cost reports the static cost estimate. An unset tier is treated as moderate,
// so a strategy is never accidentally ranked as cheap.
func (l legacyStrategy) Cost() CostEstimate {
	tier := l.cost
	if tier == "" {
		tier = CostModerate
	}
	return CostEstimate{Tier: tier, Expensive: tier == CostExpensive}
}

// Supports reports mode eligibility from the modes map.
func (l legacyStrategy) Supports(mode Mode) SupportResult {
	if l.modes == nil {
		return SupportResult{Supported: true}
	}
	if _, ok := l.modes[mode]; ok {
		return SupportResult{Supported: true}
	}
	return SupportResult{
		Supported: false,
		Reason:    fmt.Sprintf("not applicable in %s mode (supported: %s)", mode, l.modeList()),
	}
}

// orderIn gives the run order of this strategy within mode, and whether it
// supports that mode. The registry uses it to sequence eligible strategies.
func (l legacyStrategy) orderIn(mode Mode) (int, bool) {
	if l.modes == nil {
		return 0, true
	}
	o, ok := l.modes[mode]
	return o, ok
}

// modeList renders the supported modes in a stable order for messages.
func (l legacyStrategy) modeList() string {
	ms := make([]string, 0, len(l.modes))
	for m := range l.modes {
		ms = append(ms, string(m))
	}
	sort.Strings(ms)
	if len(ms) == 0 {
		return "none"
	}
	return strings.Join(ms, ", ")
}

// supportedModes lists this strategy's modes in a stable order.
func (l legacyStrategy) supportedModes() []Mode {
	ms := make([]Mode, 0, len(l.modes))
	for m := range l.modes {
		ms = append(ms, m)
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i] < ms[j] })
	return ms
}

// newLegacy builds a legacy wrapper around a bound solver method.
func newLegacy(id, desc string, cost CostTier, modes map[Mode]int, run func(context.Context) (bool, error)) legacyStrategy {
	return legacyStrategy{id: id, desc: desc, cost: cost, modes: modes, run: run}
}

// formatStrategy is the format-string leak strategy: local-only and gated on a
// confirmed format-string finding, so it is run specially (before the registry
// set) rather than registered.
func (s *solver) formatStrategy() legacyStrategy {
	return newLegacy("format_string", "read a flag via format-string %p/%s leaks over one connection",
		CostCheap, map[Mode]int{ModeLocal: 0}, s.formatStringStrategy)
}

// buildRegistry registers every non-format strategy once, with its per-mode run
// order and cost tier. This single registry replaces the previously duplicated
// local and remote ordered lists: eligible(mode) returns them ranked (cheaper
// first, expensive deferred) and explains which strategies are rejected. The
// mode orders below match the historical sequences; ranking then defers the
// expensive strategies behind the rest.
func (s *solver) buildRegistry() *registry {
	r := newRegistry()
	r.register(newLegacy("fmt_got_overwrite", "format-string GOT overwrite with %hhn to redirect a called function", CostModerate, map[Mode]int{ModeLocal: 1}, s.fmtGotOverwriteStrategy))
	r.register(newLegacy("fmt_write_ret", "format-string write to a saved return address (defeats full RELRO)", CostModerate, map[Mode]int{ModeLocal: 2}, s.fmtWriteRetStrategy))
	r.register(newLegacy("heap_uaf", "menu-driven heap use-after-free overwriting a function pointer", CostModerate, map[Mode]int{ModeLocal: 3, ModeRemote: 6}, s.heapUAFStrategy))
	r.register(newLegacy("stack_overwrite", "stack buffer overflow setting a guard variable or redirecting to a win function", CostModerate, map[Mode]int{ModeLocal: 4}, s.stackOverwriteStrategy))
	r.register(newLegacy("rop_ret2win_args", "two-argument ret2win ROP via pop rdi/pop rsi gadgets", CostCheap, map[Mode]int{ModeLocal: 5}, s.ropRet2winArgsStrategy))
	r.register(newLegacy("rop_execve", "ret2syscall execve(\"/bin/sh\") ROP from syscall gadgets", CostCheap, map[Mode]int{ModeLocal: 6, ModeRemote: 3}, s.ropExecveStrategy))
	r.register(newLegacy("ret2plt", "call an imported function (system/exec*) with an in-binary string argument", CostCheap, map[Mode]int{ModeLocal: 7, ModeRemote: 4}, s.ret2pltStrategy))
	r.register(newLegacy("shellcode", "executable-stack shellcode delivered over a live session", CostModerate, map[Mode]int{ModeLocal: 8, ModeRemote: 1}, s.shellcodeStrategy))
	r.register(newLegacy("ret2libc", "ret2libc using a leaked libc address resolved against a provided libc", CostModerate, map[Mode]int{ModeLocal: 9, ModeRemote: 2}, s.ret2libcStrategy))
	r.register(newLegacy("canary_ret2win", "leak the stack canary, then overflow preserving it to reach a win function", CostModerate, map[Mode]int{ModeLocal: 10, ModeRemote: 5}, s.canaryStrategy))
	r.register(newLegacy("angr_logic", "symbolic execution (angr) of logic/argv/stdin puzzles, replayed concretely", CostExpensive, map[Mode]int{ModeLocal: 11}, s.angrStrategy))
	r.register(newLegacy("partial_overwrite", "PIE partial overwrite of a saved return address with no leak", CostExpensive, map[Mode]int{ModeLocal: 12, ModeRemote: 8}, s.partialOverwriteStrategy))
	r.register(newLegacy("rop_planner", "synthesize multi-argument and chained calls with the ROP planner", CostModerate, map[Mode]int{ModeLocal: 13, ModeRemote: 9}, s.ropPlannerStrategy))
	r.register(newLegacy("stack_overwrite_session", "overflow-to-shell brute force over a live session", CostExpensive, map[Mode]int{ModeRemote: 7}, s.stackOverwriteSessionStrategy))
	return r
}

// Catalog returns every strategy's static identity in a stable order, with no
// duplicates and needing no target. It reflects the registry plus the
// format-string strategy.
func Catalog() []StrategyInfo {
	s := &solver{} // only method identities are read; nothing is executed
	var out []StrategyInfo
	seen := map[string]bool{}
	add := func(st legacyStrategy) {
		if seen[st.ID()] {
			return
		}
		seen[st.ID()] = true
		out = append(out, StrategyInfo{ID: st.ID(), Description: st.Description(), Modes: st.supportedModes(), Cost: st.Cost().Tier})
	}
	add(s.formatStrategy())
	for _, st := range s.buildRegistry().all() {
		add(st)
	}
	return out
}
