package solve

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/execution"
	"github.com/MoriartyPuth/PwnProbes/internal/extract"
)

// scriptSession is a fake interactive target for the composed chain: it replies
// to the format-string trigger with a leaked libc pointer, then to the overflow
// payload with the flag. It lets the two-stage flow be driven deterministically,
// with no real binary.
type scriptSession struct {
	leakLine string // returned after the first Send (the leak trigger)
	flagLine string // returned after the second Send (the overflow)
	sends    int
	lastRecv string
}

func (s *scriptSession) Send(b []byte) error {
	s.sends++
	switch s.sends {
	case 1:
		s.lastRecv = s.leakLine
	case 2:
		s.lastRecv = "" // shell comes up, flag arrives on the drive-shell send
	default:
		s.lastRecv = s.flagLine
	}
	return nil
}
func (s *scriptSession) SendLine(b []byte) error { return s.Send(b) }
func (s *scriptSession) RecvUntil([]byte, time.Duration) ([]byte, error) {
	return []byte(s.lastRecv), nil
}
func (s *scriptSession) RecvUntilIdle(time.Duration) []byte {
	r := s.lastRecv
	s.lastRecv = ""
	return []byte(r)
}
func (s *scriptSession) Received() string { return "" }
func (s *scriptSession) Close() error     { return nil }

// scriptExecutor hands out one scripted session.
type scriptExecutor struct{ sess execution.Session }

func (e *scriptExecutor) Run(context.Context, execution.Request) (execution.Result, error) {
	return execution.Result{}, nil
}
func (e *scriptExecutor) Open(context.Context, execution.SessionRequest) (execution.Session, error) {
	return e.sess, nil
}

// The composed chain recovers a flag that no single strategy could: it must send
// a format-string trigger to leak libc, establish the base, then consume that
// base in a ret2libc overflow. The scripted target discloses the flag only after
// that sequence.
func TestChainLeakRet2libcSolvesComposedClass(t *testing.T) {
	ex, _ := extract.New("")
	base := uint64(0x7f1111100000)
	syms := map[string]uint64{"puts": 0x80ed0, "system": 0x50d60}
	leak := base + syms["puts"] // the target leaks puts, not system

	sess := &scriptSession{
		leakLine: fmt.Sprintf("%#x\n", leak),
		flagLine: "flag{chain_as_unit}\n",
	}
	tc := &TargetContext{Target: Target{Bits: 64}}
	rep := &Report{Attempts: []Attempt{}, Flags: []string{}}
	s := &solver{ex: ex, path: "/tmp/vuln", remote: "r:1", report: rep, exec: &scriptExecutor{sess: sess}, tc: tc}

	rr := ret2libcResolved{popRDI: 0x401283, hasRet: true, ret: 0x40101a, sysOff: syms["system"], binshOff: 0x1d8678, syms: syms}
	done, err := s.runLeakRet2libc(context.Background(), rr)
	if err != nil {
		t.Fatalf("chain error: %v", err)
	}
	if !done || !rep.Solved || len(rep.Flags) == 0 || rep.Flags[0] != "flag{chain_as_unit}" {
		t.Fatalf("composed chain should recover the flag; done=%v solved=%v flags=%v", done, rep.Solved, rep.Flags)
	}
	// The leak step recorded the base as shared Knowledge and as an intermediate
	// primitive the exploit step consumed.
	if tc.Knowledge.LibcBase == nil || *tc.Knowledge.LibcBase != base {
		t.Errorf("libc base not established in Knowledge: %v", tc.Knowledge.LibcBase)
	}
	var sawLibcLeak bool
	for _, p := range tc.Primitives {
		if p.Kind == PrimitiveLeak && p.Domain == DomainLibc {
			sawLibcLeak = true
		}
	}
	if !sawLibcLeak {
		t.Errorf("expected a recorded libc leak primitive, got %+v", tc.Primitives)
	}
	// The winning attempt is attributed to the composed chain.
	if rep.Winning == nil || rep.Winning.Strategy != "chain_leak_ret2libc" {
		t.Errorf("winning strategy = %+v, want chain_leak_ret2libc", rep.Winning)
	}
}

// A libc base already in Knowledge is reused — the chain does not re-derive it.
func TestLibcBaseForReusesKnowledge(t *testing.T) {
	known := uint64(0x7faa00000000)
	tc := &TargetContext{Target: Target{Bits: 64}, Knowledge: Knowledge{LibcBase: &known}}
	s := &solver{tc: tc}
	// Pass empty leaks/syms: if it tried to derive, it would fail; reuse returns known.
	got, ok := s.libcBaseFor(nil, nil)
	if !ok || got != known {
		t.Errorf("libcBaseFor should reuse the known base %#x, got %#x ok=%v", known, got, ok)
	}
	// No new finding/primitive recorded when reusing.
	if len(tc.Findings) != 0 || len(tc.Primitives) != 0 {
		t.Errorf("reuse should record nothing new: findings=%d primitives=%d", len(tc.Findings), len(tc.Primitives))
	}
}

// The strategy is registered and classified expensive, so PR 6's ranking defers
// it behind every cheaper technique (it never pre-empts a direct recipe).
func TestChainStrategyIsDeferred(t *testing.T) {
	found := false
	for _, st := range Catalog() {
		if st.ID == "chain_leak_ret2libc" {
			found = true
			if st.Cost != CostExpensive {
				t.Errorf("chain strategy cost = %s, want expensive (deferred)", st.Cost)
			}
		}
	}
	if !found {
		t.Error("chain_leak_ret2libc should be in the catalog")
	}
	// In the eligible local order, it must come after a cheap strategy like ret2plt.
	s := &solver{report: &Report{}}
	run, _ := s.buildRegistry().eligible(ModeLocal)
	ci, ri := -1, -1
	for i, st := range run {
		switch st.ID() {
		case "chain_leak_ret2libc":
			ci = i
		case "ret2plt":
			ri = i
		}
	}
	if ci < 0 || ri < 0 || ci < ri {
		t.Errorf("chain (%d) should be ordered after ret2plt (%d)", ci, ri)
	}
}
