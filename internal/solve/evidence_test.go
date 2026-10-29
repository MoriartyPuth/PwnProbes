package solve

import (
	"testing"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/detect"
	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
)

// A crash finding from the detector must translate to an Observed observation
// with no interpretation — it must never become an overflow/control claim.
func TestTranslateDetectionCrashStaysObserved(t *testing.T) {
	d := detect.Report{Findings: []detect.Finding{
		{Kind: "crash", Status: "observed", Evidence: "long_input terminated with SIGSEGV; cause and control are unconfirmed"},
	}}
	fs := translateDetection(d, time.Unix(0, 0))
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Kind != FindingCrash {
		t.Errorf("kind = %q, want %q", f.Kind, FindingCrash)
	}
	if f.Status != StatusObserved {
		t.Errorf("status = %q, want %q (a crash is only ever observed)", f.Status, StatusObserved)
	}
	if f.Interpretation != "" {
		t.Errorf("crash must carry no interpretation, got %q", f.Interpretation)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].Type != "signal" {
		t.Errorf("want one signal observation, got %+v", f.Evidence)
	}
}

// A confirmed format-string behavior translates to a Confirmed finding.
func TestTranslateDetectionFormatStringConfirmed(t *testing.T) {
	d := detect.Report{Findings: []detect.Finding{
		{Kind: "format_string", Status: "confirmed_behavior", Evidence: "two expanded %p fields"},
	}}
	fs := translateDetection(d, time.Unix(0, 0))
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	if fs[0].Kind != FindingFormatString || fs[0].Status != StatusConfirmed {
		t.Errorf("got kind=%q status=%q, want format_string/confirmed", fs[0].Kind, fs[0].Status)
	}
	if fs[0].Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0", fs[0].Confidence)
	}
}

// The verification ladder must be strictly ordered, with off-ladder statuses at
// rank 0 so they never outrank a real rung.
func TestStatusRankOrdering(t *testing.T) {
	ladder := []VerificationStatus{StatusObserved, StatusConfirmed, StatusPrimitiveEstablished, StatusExploitabilityEstablished, StatusObjectiveMet}
	for i := 1; i < len(ladder); i++ {
		if StatusRank(ladder[i]) <= StatusRank(ladder[i-1]) {
			t.Errorf("rank(%s)=%d not greater than rank(%s)=%d", ladder[i], StatusRank(ladder[i]), ladder[i-1], StatusRank(ladder[i-1]))
		}
	}
	for _, off := range []VerificationStatus{StatusInconclusive, StatusUnsupported} {
		if StatusRank(off) != 0 {
			t.Errorf("off-ladder %s should rank 0, got %d", off, StatusRank(off))
		}
	}
}

// RecoverFlag.Verify reproduces the legacy meaning of Solved and grades partial
// progress from the evidence, never promoting a crash to a solve.
func TestRecoverFlagVerify(t *testing.T) {
	o := RecoverFlag{}
	cases := []struct {
		name string
		out  Outcome
		want VerificationStatus
	}{
		{"flag recovered", Outcome{Flags: []string{"FLAG{x}"}, HighestStatus: StatusObserved}, StatusObjectiveMet},
		{"confirmed only", Outcome{HighestStatus: StatusConfirmed}, StatusConfirmed},
		{"crash only", Outcome{HighestStatus: StatusObserved}, StatusObserved},
		{"nothing", Outcome{HighestStatus: StatusInconclusive}, StatusInconclusive},
	}
	for _, c := range cases {
		if got := o.Verify(c.out).Status; got != c.want {
			t.Errorf("%s: status = %q, want %q", c.name, got, c.want)
		}
	}
	// A flag present must win even if some finding reached only Observed.
	if v := o.Verify(Outcome{Flags: []string{"FLAG{y}"}, HighestStatus: StatusObserved}); len(v.Flags) != 1 {
		t.Errorf("objective-met verification should carry the flags, got %+v", v.Flags)
	}
}

// capabilitiesOf reads mitigations into booleans; unknown/absent is false, and
// RELRO is full only when the status says so.
func TestCapabilitiesOf(t *testing.T) {
	bin := inspect.Report{
		ExecutionSupported: true,
		Protections: map[string]inspect.Evidence{
			"nx":     {Status: "enabled"},
			"pie":    {Status: "unknown"},
			"canary": {Status: "disabled"},
			"relro":  {Status: "full"},
		},
	}
	c := capabilitiesOf(bin)
	if !c.NX || c.PIE || c.Canary || !c.FullRELRO || !c.ExecutionSupported {
		t.Errorf("capabilities misread: %+v", c)
	}
}

// newTargetContext carries the binary's identity into Target and starts with an
// empty, non-nil findings slice.
func TestNewTargetContextIdentity(t *testing.T) {
	bin := inspect.Report{SHA256: "abc123", Architecture: "amd64", Bits: 64, Protections: map[string]inspect.Evidence{}}
	tc := newTargetContext(bin, "/tmp/vuln", "local", "")
	if tc.Target.SHA256 != "abc123" || tc.Target.Bits != 64 || tc.Target.Mode != "local" {
		t.Errorf("target identity wrong: %+v", tc.Target)
	}
	if tc.Findings == nil {
		t.Error("findings slice should be initialized, not nil")
	}
}

// recordLeaks files pointers by range and de-duplicates.
func TestRecordLeaksClassifyAndDedup(t *testing.T) {
	tc := &TargetContext{}
	tc.recordLeaks([]uint64{0x7ffff7a0d000, 0x555555556000, 0x7ffff7a0d000}) // stack-ish, heap-ish, dup
	if len(tc.Knowledge.StackLeaks) != 1 || tc.Knowledge.StackLeaks[0] != 0x7ffff7a0d000 {
		t.Errorf("stack leaks = %#x, want one 0x7ffff7a0d000", tc.Knowledge.StackLeaks)
	}
	if len(tc.Knowledge.HeapLeaks) != 1 || tc.Knowledge.HeapLeaks[0] != 0x555555556000 {
		t.Errorf("heap leaks = %#x, want one 0x555555556000", tc.Knowledge.HeapLeaks)
	}
}

// resolveLibcCached reuses an already-known libc without re-resolving, and
// returns the cached offsets with their recorded status. This exercises the
// reuse path deterministically without touching the filesystem.
func TestResolveLibcCachedReuse(t *testing.T) {
	s := &solver{tc: &TargetContext{Knowledge: Knowledge{Libc: &LibraryInfo{
		Path: "/seeded/libc.so.6", Source: "ldd", SystemOffset: 0x2f9e0, BinshOffset: 0x1d8678, Resolved: true,
	}}}}
	sys, binsh, ok := s.resolveLibcCached()
	if !ok || sys != 0x2f9e0 || binsh != 0x1d8678 {
		t.Errorf("cached resolve = (%#x, %#x, %v), want the seeded values", sys, binsh, ok)
	}
	// The cache must be untouched (still one recorded libc, same path).
	if s.tc.Knowledge.Libc.Path != "/seeded/libc.so.6" {
		t.Errorf("cache was mutated: %+v", s.tc.Knowledge.Libc)
	}
}
