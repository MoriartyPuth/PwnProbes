package rop

import "bytes"

// Call is one function invocation: jump to Func with Args placed in the System V
// argument registers (rdi, rsi, rdx, rcx, r8, r9).
type Call struct {
	Func uint64
	Args []uint64
}

// wantFor maps a call's positional arguments onto the argument registers.
func wantFor(call Call) (map[Reg]uint64, bool) {
	if len(call.Args) > len(ArgRegs) {
		return nil, false
	}
	want := map[Reg]uint64{}
	for i, v := range call.Args {
		want[ArgRegs[i]] = v
	}
	return want, true
}

// BuildCall assembles padding + register setup + the call. When align is set, a
// `ret` gadget is inserted before the function to fix a 16-byte stack alignment
// (the common movaps fault); it is ignored if the catalog has no ret gadget.
func (c *Catalog) BuildCall(offset int, call Call, align bool) ([]byte, bool) {
	return c.BuildCallSeq(offset, []Call{call}, align)
}

// BuildCallSeq assembles a chain that performs each call in order: every call's
// PLT/function stub returns onto the next call's register-setup, so the calls run
// back to back. Returns false if any call's registers cannot be set.
func (c *Catalog) BuildCallSeq(offset int, calls []Call, align bool) ([]byte, bool) {
	out := bytes.Repeat([]byte("A"), offset)
	for _, call := range calls {
		want, ok := wantFor(call)
		if !ok {
			return nil, false
		}
		frag, ok := c.SetRegs(want)
		if !ok {
			return nil, false
		}
		out = append(out, frag...)
		if align && c.HasRet {
			out = append(out, le64(c.Ret)...)
		}
		out = append(out, le64(call.Func)...)
	}
	return out, true
}
