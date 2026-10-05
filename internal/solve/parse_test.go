package solve

import (
	"reflect"
	"testing"
)

// parseLeaks keeps only pointer-width hex tokens (>= 6 digits) above 0x1000,
// de-duplicated and in first-seen order.
func TestParseLeaks(t *testing.T) {
	in := "ret=0xdeadbeef base=0x400123 low=0x000fff again=0xdeadbeef tiny=0xab"
	got := parseLeaks(in)
	want := []uint64{0xdeadbeef, 0x400123}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseLeaks = %#x, want %#x", got, want)
	}
}

func TestLastPromptLine(t *testing.T) {
	cases := map[string]string{
		"index: ":                 "index:",
		"freed\nmenu\n  size:  \n": "size:",
		"":                        "",
		"\n\n":                    "",
	}
	for in, want := range cases {
		if got := lastPromptLine(in); got != want {
			t.Fatalf("lastPromptLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyPrompt(t *testing.T) {
	cases := []struct {
		text string
		want promptRole
	}{
		{"index: ", roleIndex},
		{"which slot? ", roleIndex},
		{"size: ", roleSize},
		{"how many bytes? ", roleSize},
		{"Enter data: ", roleData},
		{"content> ", roleData},
		{"> ", roleUnknown},
		// A reappearing menu (two+ numbered option lines) stops the action.
		{"1. create\n2. delete\n3. edit\n> ", roleUnknown},
	}
	for _, c := range cases {
		if got := classifyPrompt(c.text); got != c.want {
			t.Fatalf("classifyPrompt(%q) = %d, want %d", c.text, got, c.want)
		}
	}
}

func TestInferMenu(t *testing.T) {
	banner := "1. create\n2. delete\n3. edit\n4. use\n5. exit\n> "
	m, ok := inferMenu(banner)
	if !ok {
		t.Fatalf("inferMenu failed on a complete menu")
	}
	if m.create != 1 || m.del != 2 || m.reclaim != 3 || m.use != 4 {
		t.Fatalf("inferMenu mapping wrong: %+v", m)
	}

	// Synonyms must also resolve.
	syn := "1. Allocate\n2. Release\n3. Modify\n4. Trigger\n5. Quit\n"
	if m2, ok2 := inferMenu(syn); !ok2 || m2.create != 1 || m2.del != 2 || m2.reclaim != 3 || m2.use != 4 {
		t.Fatalf("inferMenu synonyms wrong: %+v ok=%v", m2, ok2)
	}

	// Missing the free action means the UAF chain cannot be driven.
	if _, ok3 := inferMenu("1. create\n2. edit\n3. use\n"); ok3 {
		t.Fatalf("inferMenu should fail without a free/delete option")
	}
}
