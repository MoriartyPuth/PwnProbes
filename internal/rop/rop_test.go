package rop

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// gadget bytes: pop rdi; pop rsi; pop rdx; ret | pop rcx; ret | pop r8; ret | syscall; ret
// addresses are base + offset into the blob.
func sampleCatalog(base uint64) (*Catalog, map[string]uint64) {
	blob := []byte{
		0x5f, 0x5e, 0x5a, 0xc3, // 0: pop rdi; pop rsi; pop rdx; ret
		0x59, 0xc3, // 4: pop rcx; ret
		0x41, 0x58, 0xc3, // 6: pop r8; ret
		0x0f, 0x05, 0xc3, // 9: syscall; ret
	}
	c := Build([]Section{{Addr: base, Data: blob}})
	off := map[string]uint64{"multi": base, "rcx": base + 4, "r8": base + 6, "syscall": base + 9}
	return c, off
}

func TestCatalogFindsPopsRetSyscall(t *testing.T) {
	c, off := sampleCatalog(0x400000)
	// The 3-pop gadget and its sub-gadgets (starting at each pop) must be present.
	want := map[uint64][]Reg{
		off["multi"]:     {RDI, RSI, RDX},
		off["multi"] + 1: {RSI, RDX},
		off["multi"] + 2: {RDX},
		off["rcx"]:       {RCX},
		off["r8"]:        {R8},
	}
	got := map[uint64][]Reg{}
	for _, g := range c.Pops {
		got[g.Addr] = g.Regs
	}
	for a, regs := range want {
		if !reflect.DeepEqual(got[a], regs) {
			t.Fatalf("pop gadget at %#x = %v, want %v", a, got[a], regs)
		}
	}
	if !c.HasSyscall || c.Syscall != off["syscall"] {
		t.Fatalf("syscall gadget: has=%v addr=%#x want %#x", c.HasSyscall, c.Syscall, off["syscall"])
	}
	if !c.HasRet {
		t.Fatalf("no ret gadget found")
	}
}

func words(b []byte) []uint64 {
	var w []uint64
	for i := 0; i+8 <= len(b); i += 8 {
		w = append(w, binary.LittleEndian.Uint64(b[i:]))
	}
	return w
}

func TestSetRegsPrefersCoveringGadget(t *testing.T) {
	c, off := sampleCatalog(0x400000)
	frag, ok := c.SetRegs(map[Reg]uint64{RDI: 0xaaaa, RSI: 0xbbbb, RDX: 0xcccc})
	if !ok {
		t.Fatal("SetRegs failed")
	}
	// Expect the 3-pop gadget followed by the values in pop order.
	if got, want := words(frag), []uint64{off["multi"], 0xaaaa, 0xbbbb, 0xcccc}; !reflect.DeepEqual(got, want) {
		t.Fatalf("frag = %#x, want %#x", got, want)
	}
}

func TestSetRegsComposesSingles(t *testing.T) {
	// Only single-pop gadgets available: pop rdi; ret and pop rsi; ret.
	blob := []byte{0x5f, 0xc3, 0x5e, 0xc3}
	c := Build([]Section{{Addr: 0x401000, Data: blob}})
	frag, ok := c.SetRegs(map[Reg]uint64{RDI: 1, RSI: 2})
	if !ok {
		t.Fatal("SetRegs(singles) failed")
	}
	// Deterministic register order is RDI(7) then RSI(6)? sorted ascending => RSI(6), RDI(7).
	if got, want := words(frag), []uint64{0x401002, 2, 0x401000, 1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("frag = %#x, want %#x", got, want)
	}
	// A register with no gadget cannot be set.
	if _, ok := c.SetRegs(map[Reg]uint64{RDX: 9}); ok {
		t.Fatal("expected SetRegs to fail for RDX with no gadget")
	}
}

func TestBuildCallSeq(t *testing.T) {
	c, off := sampleCatalog(0x400000)
	chain, ok := c.BuildCallSeq(16, []Call{
		{Func: 0x401111, Args: []uint64{1, 2, 3}},
		{Func: 0x402222, Args: []uint64{1, 2, 3}},
	}, false)
	if !ok {
		t.Fatal("BuildCallSeq failed")
	}
	if !bytes.HasPrefix(chain, bytes.Repeat([]byte("A"), 16)) {
		t.Fatal("missing padding")
	}
	got := words(chain[16:])
	want := []uint64{
		off["multi"], 1, 2, 3, 0x401111,
		off["multi"], 1, 2, 3, 0x402222,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chain = %#x, want %#x", got, want)
	}
}

func TestHarvestConstants(t *testing.T) {
	// movabs rax, 0xdeadbeefdeadbeef  (48 b8 + 8 bytes), twice; mov eax, 5 once.
	m := []byte{0x48, 0xb8, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde}
	blob := append(append([]byte{}, m...), m...)
	blob = append(blob, 0xb8, 0x05, 0x00, 0x00, 0x00) // mov eax, 5
	c := HarvestConstants([]Section{{Addr: 0x400000, Data: blob}})
	if c[0xdeadbeefdeadbeef] != 2 {
		t.Fatalf("movabs count = %d, want 2", c[0xdeadbeefdeadbeef])
	}
	if c[5] != 1 {
		t.Fatalf("mov imm32 count = %d, want 1", c[5])
	}
}
