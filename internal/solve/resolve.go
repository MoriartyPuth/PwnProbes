package solve

import (
	"debug/elf"
	"fmt"

	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
)

// This file begins "finish plan/execute" (roadmap §30 PR 16): the static
// recognition a strategy performs — scanning the ELF for gadgets, PLT stubs, and
// command strings — is factored out of its Run into a shared Resolve. The Plan
// and the Execute path then consume the *same* resolution, so an inspected plan
// carries the concrete addresses execution will use and cannot drift from them.
// ret2plt is the first strategy fully split this way; others follow incrementally
// and remain as they are until then.

// Ret2pltResolution is the static material a ret2plt attempt needs, recognized
// once from the binary: a `pop rdi; ret` gadget, an optional stack-aligning
// `ret`, the callable exec-family PLT stubs, and in-binary command strings. It is
// produced without executing the target.
type Ret2pltResolution struct {
	PopRDI    uint64 `json:"pop_rdi,omitempty"`
	HasPopRDI bool   `json:"has_pop_rdi"`
	Ret       uint64 `json:"ret,omitempty"`
	HasRet    bool   `json:"has_ret"`
	Calls     []pltCall
	Strings   []strEntry
}

// Feasible reports whether the resolution has the minimum a ret2plt chain needs:
// a pop-rdi gadget, a callable exec stub, and a command string.
func (r Ret2pltResolution) Feasible() bool {
	return r.HasPopRDI && len(r.Calls) > 0 && len(r.Strings) > 0
}

// resolveRet2pltFrom recognizes the ret2plt material in the binary at path. It
// opens the ELF read-only (no execution) and returns an empty resolution if the
// file cannot be read, so callers can treat "not resolvable" uniformly.
func resolveRet2pltFrom(bin inspect.Report, path string) Ret2pltResolution {
	var res Ret2pltResolution
	if bin.Bits != 64 || bin.Protections["pie"].Status == "enabled" {
		return res
	}
	f, err := elf.Open(path)
	if err != nil {
		return res
	}
	defer f.Close()

	res.PopRDI, res.HasPopRDI = findGadget(f, []byte{0x5f, 0xc3}) // pop rdi; ret
	res.Ret, res.HasRet = findGadget(f, []byte{0xc3})             // ret (alignment)

	stubs := pltStubs(f)    // GOT slot -> PLT stub address
	got := pltGotEntries(f) // symbol name -> GOT slot
	res.Strings = commandStrings(f)
	if a, ok := findBinSh(f); ok {
		res.Strings = append(res.Strings, strEntry{addr: a, text: "/bin/sh"})
	}
	for _, name := range []string{"system", "execl", "execlp", "execvp"} {
		if slot, ok := got[name]; ok {
			if stub, ok2 := stubs[slot]; ok2 {
				res.Calls = append(res.Calls, pltCall{name: name, addr: stub})
			}
		}
	}
	return res
}

// resolveRet2plt resolves ret2plt material from the shared context's target.
func resolveRet2plt(tc *TargetContext) Ret2pltResolution {
	return resolveRet2pltFrom(tc.Binary, tc.Target.Path)
}

// hexAddr formats an address for a plan step; "?" when not resolved.
func hexAddr(v uint64, ok bool) string {
	if !ok {
		return "?"
	}
	return fmt.Sprintf("%#x", v)
}
