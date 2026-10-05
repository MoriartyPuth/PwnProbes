package extract

import (
	"reflect"
	"testing"
)

// The extractor's core guarantee: a flag counts only when the program discloses
// it, never when the caller's own input is reflected back.
func TestFindDisclosedVsEchoed(t *testing.T) {
	e, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	out := "banner\nFLAG{disclosed_secret}\n"
	cands := e.Find(out, []byte("some other input"), "stdout")
	if len(cands) != 1 {
		t.Fatalf("want 1 candidate, got %d: %+v", len(cands), cands)
	}
	if cands[0].Value != "FLAG{disclosed_secret}" || cands[0].Echoed {
		t.Fatalf("unexpected candidate: %+v", cands[0])
	}
	if cands[0].Source != "stdout" {
		t.Fatalf("source not propagated: %q", cands[0].Source)
	}

	// The same shape, but supplied in the input, must be marked echoed.
	echo := "FLAG{echoed_back}"
	cands = e.Find("prefix "+echo+" suffix", []byte("please print "+echo), "stdout")
	if len(cands) != 1 || !cands[0].Echoed {
		t.Fatalf("echoed match not flagged: %+v", cands)
	}
}

func TestFindDeduplicatesInFirstSeenOrder(t *testing.T) {
	e, _ := New("")
	out := "flag{b} flag{a} flag{b} flag{a}"
	got := e.Find(out, nil, "s")
	if len(got) != 2 || got[0].Value != "flag{b}" || got[1].Value != "flag{a}" {
		t.Fatalf("dedupe/order wrong: %+v", got)
	}
}

func TestRecoveredDropsEchoedAndDupes(t *testing.T) {
	cands := []Candidate{
		{Value: "flag{keep}", Echoed: false},
		{Value: "flag{echo}", Echoed: true},
		{Value: "flag{keep}", Echoed: false}, // duplicate
		{Value: "flag{also}", Echoed: false},
	}
	got := Recovered(cands)
	want := []string{"flag{keep}", "flag{also}"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Recovered = %v, want %v", got, want)
	}
	// Recovered must always return a non-nil slice so JSON encodes [] not null.
	if Recovered(nil) == nil {
		t.Fatalf("Recovered(nil) returned nil slice")
	}
}

// A flag smuggled through a %p stack dump never appears literally; DecodeLeak
// reassembles it from the little-endian pointer words.
func TestDecodeLeakReassemblesLittleEndian(t *testing.T) {
	// "flagABCD" as two little-endian 64-bit words: 'galf' then 'DCBA' bytes.
	// 0x67616c66 = "galf" (low->high f,l,a,g); printed big-endian in the token,
	// DecodeLeak walks it high-index-first to recover f,l,a,g.
	leak := "0x67616c66 0x44434241"
	got := DecodeLeak(leak)
	if got != "flagABCD" {
		t.Fatalf("DecodeLeak = %q, want %q", got, "flagABCD")
	}
	// A pattern applied to the decoded text recovers a flag absent from stdout.
	e, _ := New(`flag\{[^}]+\}`)
	decoded := DecodeLeak("0x7b67616c66 0x7d646c72") // "{galf" , "}dlr"
	cands := e.Find(decoded, nil, "stack_leak")
	if len(cands) != 1 || cands[0].Value != "flag{rld}" {
		t.Fatalf("decoded-flag recovery failed: decoded=%q cands=%+v", decoded, cands)
	}
}

func TestNewRejectsBadPattern(t *testing.T) {
	if _, err := New("("); err == nil {
		t.Fatalf("expected error for invalid regexp")
	}
}
