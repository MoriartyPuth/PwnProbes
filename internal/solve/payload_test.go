package solve

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/MoriartyPuth/PwnProbes/internal/extract"
	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

func newSolver(t *testing.T) *solver {
	t.Helper()
	ex, err := extract.New("")
	if err != nil {
		t.Fatalf("extract.New: %v", err)
	}
	return &solver{ex: ex, report: &Report{Attempts: []Attempt{}, Flags: []string{}}}
}

// finalize must record the byte-exact payload as hex (so a payload with NUL and
// non-UTF-8 bytes survives JSON) and mark the report solved when a non-echoed
// flag was disclosed.
func TestFinalizeSerializesPayloadAndRecordsSolve(t *testing.T) {
	s := newSolver(t)
	payload := []byte{0x00, 0x41, 0xff, 0x90, 0x0a} // NUL + invalid UTF-8 + newline
	res := runner.Result{Outcome: "session", ExitCode: -1, Stdout: "shell\nflag{heap_uaf_pwned}\n"}
	cands := s.ex.Find(res.Stdout, payload, "session")

	if done := s.finalize("heap_uaf", "fn_offset=0", payload, res, cands); !done {
		t.Fatalf("finalize returned false for a disclosed flag")
	}
	if !s.report.Solved {
		t.Fatalf("report not marked solved")
	}
	if len(s.report.Flags) != 1 || s.report.Flags[0] != "flag{heap_uaf_pwned}" {
		t.Fatalf("flags wrong: %v", s.report.Flags)
	}
	if s.report.Winning == nil {
		t.Fatalf("winning attempt not set")
	}
	wantHex := hex.EncodeToString(payload)
	if s.report.Winning.PayloadHex != wantHex {
		t.Fatalf("PayloadHex = %q, want %q", s.report.Winning.PayloadHex, wantHex)
	}

	// The attempt must round-trip through JSON (invalid UTF-8 is carried as hex,
	// never corrupting the document) and the hex must decode back to the bytes.
	blob, err := json.Marshal(s.report.Winning)
	if err != nil {
		t.Fatalf("marshal winning attempt: %v", err)
	}
	var back Attempt
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, err := hex.DecodeString(back.PayloadHex)
	if err != nil {
		t.Fatalf("decode payload_hex: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload_hex round-trip = %x, want %x", got, payload)
	}
}

// An echoed flag (present in the payload) is never counted as a solve.
func TestFinalizeIgnoresEchoedFlag(t *testing.T) {
	s := newSolver(t)
	payload := []byte("please print flag{echoed_back}")
	res := runner.Result{Outcome: "exited", Stdout: "you said flag{echoed_back}"}
	cands := s.ex.Find(res.Stdout, payload, "stdout")

	if done := s.finalize("stack_overwrite", "", payload, res, cands); done {
		t.Fatalf("finalize counted an echoed flag as solved")
	}
	if s.report.Solved {
		t.Fatalf("report marked solved on an echoed flag")
	}
	if len(s.report.Attempts) != 1 {
		t.Fatalf("attempt not recorded: %d", len(s.report.Attempts))
	}
}
