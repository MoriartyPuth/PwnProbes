// Package extract recovers flag-shaped strings from captured program output.
//
// The central distinction it enforces is between a flag the program disclosed
// and bytes the caller supplied that the program merely echoed. A match that
// also appears in the input is reported as echoed and is never counted as a
// recovered flag: reflecting attacker-controlled input is not evidence that a
// secret was discovered.
package extract

import (
	"bytes"
	"encoding/hex"
	"regexp"
	"strings"
)

// DefaultPattern matches the common CTF flag shape name{...}: a short prefix of
// identifier characters, then a braced body that is non-empty and free of a
// closing brace or newline. The prefix excludes '.' and '+' on purpose: when a
// flag is recovered from a stack leak it often sits in memory next to the
// format-string buffer (for example "%p."), and allowing those characters in
// the prefix would splice the neighbour into the match. It is still broad; a
// caller that knows the exact prefix (for example HTB or flag) should pass a
// tighter pattern.
const DefaultPattern = `[A-Za-z][A-Za-z0-9_-]*\{[^}\n]{1,512}\}`

var hexToken = regexp.MustCompile(`0x[0-9a-fA-F]+`)

// Candidate is a single pattern match found in searched text.
type Candidate struct {
	Value  string `json:"value"`
	Echoed bool   `json:"echoed"`           // also present in the supplied input
	Source string `json:"source,omitempty"` // where it was found, e.g. "stdout"
}

// Extractor applies one compiled pattern to captured output.
type Extractor struct {
	re *regexp.Regexp
}

// New compiles pattern, falling back to DefaultPattern when pattern is empty.
func New(pattern string) (*Extractor, error) {
	if pattern == "" {
		pattern = DefaultPattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return &Extractor{re: re}, nil
}

// Find returns the unique pattern matches in output, in first-seen order. A
// match whose value is a substring of input is flagged Echoed, meaning the
// program reflected caller-supplied bytes rather than revealing a secret. The
// source label is attached to every candidate for provenance in reports.
func (e *Extractor) Find(output string, input []byte, source string) []Candidate {
	matches := e.re.FindAllString(output, -1)
	out := make([]Candidate, 0, len(matches))
	seen := map[string]bool{}
	for _, m := range matches {
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, Candidate{Value: m, Echoed: bytes.Contains(input, []byte(m)), Source: source})
	}
	return out
}

// Recovered returns the de-duplicated values of candidates that were not echoed,
// preserving first-seen order. These are the flags the program disclosed that
// the caller did not already supply.
func Recovered(cands []Candidate) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, c := range cands {
		if c.Echoed || seen[c.Value] {
			continue
		}
		seen[c.Value] = true
		out = append(out, c.Value)
	}
	return out
}

// DecodeLeak reassembles the ASCII payload smuggled through a run of pointer
// leaks. Each 0x... token is treated as a little-endian word (its width taken
// from the number of hex digits) and its printable bytes are concatenated in
// output order. A format-string dump such as "%p.%p.%p" prints stack words that
// often contain flag bytes in little-endian; searching the decoded text with
// the same pattern recovers a flag that never appears literally in stdout. The
// raw hex tokens from the caller's own input, if any, are decoded too, so the
// caller must still screen results for echoes.
func DecodeLeak(output string) string {
	var b strings.Builder
	for _, tok := range hexToken.FindAllString(output, -1) {
		digits := tok[2:]
		if len(digits)%2 == 1 {
			digits = "0" + digits
		}
		raw, err := hex.DecodeString(digits)
		if err != nil {
			continue
		}
		for i := len(raw) - 1; i >= 0; i-- { // little-endian: low byte printed last
			if raw[i] >= 0x20 && raw[i] < 0x7f {
				b.WriteByte(raw[i])
			}
		}
	}
	return b.String()
}
