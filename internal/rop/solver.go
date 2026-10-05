package rop

import "sort"

// SetRegs returns the chain fragment that loads the requested registers with the
// given values, and whether it could be built from the catalog's pop gadgets. It
// prefers a single pop-sequence gadget that covers the wanted registers (filling
// any extra popped registers with zero), and otherwise composes per-register
// `pop reg; ret` gadgets. Registers not requested are left untouched.
func (c *Catalog) SetRegs(want map[Reg]uint64) ([]byte, bool) {
	if len(want) == 0 {
		return nil, true
	}

	// Candidate single gadgets whose popped set covers `want`, ranked by fewest
	// popped registers (least collateral clobber / shortest chain).
	var covering []PopGadget
	for _, g := range c.Pops {
		set := map[Reg]bool{}
		for _, r := range g.Regs {
			set[r] = true
		}
		covers := true
		for r := range want {
			if !set[r] {
				covers = false
				break
			}
		}
		if covers {
			covering = append(covering, g)
		}
	}
	if len(covering) > 0 {
		sort.SliceStable(covering, func(i, j int) bool {
			if len(covering[i].Regs) != len(covering[j].Regs) {
				return len(covering[i].Regs) < len(covering[j].Regs)
			}
			return covering[i].Addr < covering[j].Addr
		})
		g := covering[0]
		out := le64(g.Addr)
		for _, r := range g.Regs {
			out = append(out, le64(want[r])...) // want[r] is 0 for unrequested regs
		}
		return out, true
	}

	// Compose from single-register pop gadgets, one per wanted register.
	single := map[Reg]uint64{}
	for _, g := range c.Pops {
		if len(g.Regs) == 1 {
			if _, ok := single[g.Regs[0]]; !ok {
				single[g.Regs[0]] = g.Addr
			}
		}
	}
	var out []byte
	// Deterministic order for a stable chain.
	regs := make([]Reg, 0, len(want))
	for r := range want {
		regs = append(regs, r)
	}
	sort.Slice(regs, func(i, j int) bool { return regs[i] < regs[j] })
	for _, r := range regs {
		addr, ok := single[r]
		if !ok {
			return nil, false
		}
		out = append(out, le64(addr)...)
		out = append(out, le64(want[r])...)
	}
	return out, true
}
