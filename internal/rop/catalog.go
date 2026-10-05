// Package rop synthesizes x86-64 return-oriented chains from the gadgets found
// in a target binary. It is deliberately dependency-free: gadgets are located by
// matching the small set of opcode patterns the chains need (pop sequences, ret,
// syscall) rather than with a full disassembler. The package is pure -- it turns
// gadgets plus a high-level goal into payload bytes -- so it is unit-tested on
// byte blobs without running anything.
package rop

import "encoding/binary"

// Reg is an x86-64 general register, numbered so that RAX..RDI match the low
// three bits of their `pop` opcode (0x58..0x5f).
type Reg int

const (
	RAX Reg = iota
	RCX
	RDX
	RBX
	RSP
	RBP
	RSI
	RDI
	R8
	R9
	R10
	R11
	R12
	R13
	R14
	R15
)

// ArgRegs is the System V AMD64 integer argument order.
var ArgRegs = []Reg{RDI, RSI, RDX, RCX, R8, R9}

// PopGadget is a `pop <Regs...>; ret` gadget at Addr; Regs is in pop order (the
// order values must be laid on the stack).
type PopGadget struct {
	Addr uint64
	Regs []Reg
}

// Section is one executable region of the target: its virtual address and bytes.
type Section struct {
	Addr uint64
	Data []byte
}

// Catalog is the set of gadgets found in a binary.
type Catalog struct {
	Pops       []PopGadget
	Ret        uint64
	HasRet     bool
	Syscall    uint64
	HasSyscall bool
}

// popReg decodes a single `pop reg` encoding at d[i], returning the register, the
// number of bytes consumed, and whether it was a pop. REX.B (0x41) selects r8-r15.
func popReg(d []byte, i int) (Reg, int, bool) {
	if i < len(d) && d[i] == 0x41 && i+1 < len(d) && d[i+1] >= 0x58 && d[i+1] <= 0x5f {
		return R8 + Reg(d[i+1]-0x58), 2, true
	}
	if i < len(d) && d[i] >= 0x58 && d[i] <= 0x5f {
		return Reg(d[i] - 0x58), 1, true
	}
	return 0, 0, false
}

// Build scans the sections for the gadgets the planner uses. A pop-sequence
// gadget is recorded starting at every pop in a run that ends in `ret`, so the
// shorter sub-gadgets (entering the run partway) are available too.
func Build(secs []Section) *Catalog {
	c := &Catalog{}
	seen := map[uint64]bool{}
	for _, s := range secs {
		d := s.Data
		for i := 0; i < len(d); i++ {
			if d[i] == 0xc3 && !c.HasRet {
				c.Ret, c.HasRet = s.Addr+uint64(i), true
			}
			if d[i] == 0x0f && i+1 < len(d) && d[i+1] == 0x05 && !c.HasSyscall {
				c.Syscall, c.HasSyscall = s.Addr+uint64(i), true
			}
			// A pop run starting at i.
			if _, _, ok := popReg(d, i); !ok {
				continue
			}
			j, regs := i, []Reg{}
			for {
				r, n, ok := popReg(d, j)
				if !ok {
					break
				}
				regs = append(regs, r)
				j += n
			}
			if j < len(d) && d[j] == 0xc3 {
				addr := s.Addr + uint64(i)
				if !seen[addr] {
					seen[addr] = true
					c.Pops = append(c.Pops, PopGadget{Addr: addr, Regs: regs})
				}
			}
		}
	}
	return c
}

func le64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}
