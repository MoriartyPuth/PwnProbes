package solve

import "context"

// Strategy is the common shape every exploitation technique exposes to the
// orchestrator. In this step it carries identity and legacy execution only:
// Run drives the existing solver method unchanged, still coupling recognition,
// payload construction, execution, and verification inside one call. Later
// milestones add a side-effect-free Supports check and a Plan/Execute split;
// until a technique provides those it stays legacy execution-only, and the
// framework presents it as such rather than inventing an inspectable plan.
type Strategy interface {
	// ID is a stable machine name, used for selection, timing, and reports.
	ID() string
	// Description is a one-line human summary of what the strategy does.
	Description() string
	// Run executes the legacy strategy and reports whether it solved.
	Run(ctx context.Context) (bool, error)
}

// StrategyInfo is a strategy's static identity, independent of any target. It
// backs `pwnprobe strategies` and, later, the registry.
type StrategyInfo struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// legacyStrategy adapts an existing *solver method to the Strategy interface
// without changing its behavior.
type legacyStrategy struct {
	id   string
	desc string
	run  func(context.Context) (bool, error)
}

func (l legacyStrategy) ID() string                            { return l.id }
func (l legacyStrategy) Description() string                   { return l.desc }
func (l legacyStrategy) Run(ctx context.Context) (bool, error) { return l.run(ctx) }

// newLegacy builds a legacy wrapper around a bound solver method.
func newLegacy(id, desc string, run func(context.Context) (bool, error)) Strategy {
	return legacyStrategy{id: id, desc: desc, run: run}
}

// formatStrategy is the format-string leak strategy, gated on a confirmed
// format-string finding and run before the rest in local mode.
func (s *solver) formatStrategy() Strategy {
	return newLegacy("format_string", "read a flag via format-string %p/%s leaks over one connection", s.formatStringStrategy)
}

// localStrategies is the ordered set tried against a local subprocess, cheap and
// targeted techniques before costly brute force and symbolic execution. This
// slice is the single source of truth for local ordering and identity.
func (s *solver) localStrategies() []Strategy {
	return []Strategy{
		newLegacy("fmt_got_overwrite", "format-string GOT overwrite with %hhn to redirect a called function", s.fmtGotOverwriteStrategy),
		newLegacy("fmt_write_ret", "format-string write to a saved return address (defeats full RELRO)", s.fmtWriteRetStrategy),
		newLegacy("heap_uaf", "menu-driven heap use-after-free overwriting a function pointer", s.heapUAFStrategy),
		newLegacy("stack_overwrite", "stack buffer overflow setting a guard variable or redirecting to a win function", s.stackOverwriteStrategy),
		newLegacy("rop_ret2win_args", "two-argument ret2win ROP via pop rdi/pop rsi gadgets", s.ropRet2winArgsStrategy),
		newLegacy("rop_execve", "ret2syscall execve(\"/bin/sh\") ROP from syscall gadgets", s.ropExecveStrategy),
		newLegacy("ret2plt", "call an imported function (system/exec*) with an in-binary string argument", s.ret2pltStrategy),
		newLegacy("shellcode", "executable-stack shellcode delivered over a live session", s.shellcodeStrategy),
		newLegacy("ret2libc", "ret2libc using a leaked libc address resolved against a provided libc", s.ret2libcStrategy),
		newLegacy("canary_ret2win", "leak the stack canary, then overflow preserving it to reach a win function", s.canaryStrategy),
		newLegacy("angr_logic", "symbolic execution (angr) of logic/argv/stdin puzzles, replayed concretely", s.angrStrategy),
		newLegacy("partial_overwrite", "PIE partial overwrite of a saved return address with no leak", s.partialOverwriteStrategy),
		newLegacy("rop_planner", "synthesize multi-argument and chained calls with the ROP planner", s.ropPlannerStrategy),
	}
}

// remoteStrategies is the ordered set tried against a remote TCP service: leak
// and session techniques first, the costly overflow brute force last.
func (s *solver) remoteStrategies() []Strategy {
	return []Strategy{
		newLegacy("shellcode", "executable-stack shellcode delivered over a live session", s.shellcodeStrategy),
		newLegacy("ret2libc", "ret2libc using a leaked libc address resolved against a provided libc", s.ret2libcStrategy),
		newLegacy("rop_execve", "ret2syscall execve(\"/bin/sh\") ROP from syscall gadgets", s.ropExecveStrategy),
		newLegacy("ret2plt", "call an imported function (system/exec*) with an in-binary string argument", s.ret2pltStrategy),
		newLegacy("canary_ret2win", "leak the stack canary, then overflow preserving it to reach a win function", s.canaryStrategy),
		newLegacy("heap_uaf", "menu-driven heap use-after-free overwriting a function pointer", s.heapUAFStrategy),
		newLegacy("stack_overwrite_session", "overflow-to-shell brute force over a live session", s.stackOverwriteSessionStrategy),
		newLegacy("partial_overwrite", "PIE partial overwrite of a saved return address with no leak", s.partialOverwriteStrategy),
		newLegacy("rop_planner", "synthesize multi-argument and chained calls with the ROP planner", s.ropPlannerStrategy),
	}
}

// Catalog returns every strategy's static identity in a stable order, with no
// duplicates, needing no target. Local ordering comes first, then any remote-only
// strategy, then the format-string strategy.
func Catalog() []StrategyInfo {
	s := &solver{} // only method identities are read; nothing is executed
	seen := map[string]bool{}
	var out []StrategyInfo
	add := func(st Strategy) {
		if seen[st.ID()] {
			return
		}
		seen[st.ID()] = true
		out = append(out, StrategyInfo{ID: st.ID(), Description: st.Description()})
	}
	for _, st := range s.localStrategies() {
		add(st)
	}
	for _, st := range s.remoteStrategies() {
		add(st)
	}
	add(s.formatStrategy())
	return out
}
