package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/benchmark"
	"github.com/MoriartyPuth/PwnProbes/internal/detect"
	"github.com/MoriartyPuth/PwnProbes/internal/extract"
	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
	"github.com/MoriartyPuth/PwnProbes/internal/runner"
	"github.com/MoriartyPuth/PwnProbes/internal/solve"
)

const version = "0.2.0"

// runOutput augments a run transcript with flags the program disclosed that the
// caller did not supply. Echoed input is excluded by the extractor.
type runOutput struct {
	runner.Result
	RecoveredFlags []string `json:"recovered_flags"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := execute(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func execute(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: pwnprobe inspect|run|detect|solve|benchmark|version (use <command> -h)")
	}
	if args[0] == "version" {
		fmt.Fprintln(out, version)
		return nil
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(errOut)
	jsonMode := f.Bool("json", false, "emit structured JSON")
	timeout := f.Duration("timeout", time.Second, "per-run deadline (maximum 1 minute)")
	var input, manifest, original, baseline, pattern, remote, libc *string
	switch args[0] {
	case "inspect", "detect":
	case "run":
		input = f.String("input", "", "read stdin bytes from a file; otherwise send EOF")
		pattern = f.String("flag-pattern", "", "regexp for recovered flags; empty uses the default CTF shape")
	case "solve":
		pattern = f.String("flag-pattern", "", "regexp for recovered flags; empty uses the default CTF shape")
		remote = f.String("remote", "", "exploit a remote host:port over TCP; the path argument is a local copy for analysis")
		libc = f.String("libc", "", "path to the target's libc for ret2libc offset resolution (for a remote libc that differs from this machine's)")
	case "benchmark":
		manifest = f.String("manifest", "fixtures/manifest.json", "controlled fixture manifest")
		original = f.String("original", "", "optional original pwnpasi.py for detection comparison")
		baseline = f.String("baseline-script", "", "optional baseline adapter path")
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	emit := func(v any) error { enc := json.NewEncoder(out); enc.SetIndent("", "  "); return enc.Encode(v) }
	if args[0] == "benchmark" {
		if f.NArg() != 0 {
			return errors.New("benchmark takes flags only")
		}
		if *baseline == "" {
			*baseline = filepath.Join(filepath.Dir(*manifest), "..", "scripts", "original_detection.py")
			if *original != "" {
				if _, err := os.Stat(*baseline); err != nil {
					return errors.New("original comparison requires --baseline-script pointing to a detector adapter")
				}
			}
		}
		report, err := benchmark.Run(ctx, *manifest, *original, *baseline)
		if err != nil {
			return err
		}
		if *jsonMode {
			if err = emit(report); err != nil {
				return err
			}
		} else {
			for _, c := range report.Cases {
				fmt.Fprintf(out, "%s: passed=%v", c.Name, c.Passed)
				if c.Original != nil {
					fmt.Fprintf(out, " original_matches_expected=%v", c.Original.MatchesExpected)
				}
				fmt.Fprintln(out)
				for _, e := range c.Errors {
					fmt.Fprintln(out, "  ", e)
				}
			}
			fmt.Fprintf(out, "%d/%d fixture cases passed (detection and metadata only)\n", report.Passed, report.Total)
		}
		if report.Passed != report.Total {
			return errors.New("benchmark expectations failed")
		}
		return nil
	}
	if f.NArg() != 1 {
		return errors.New("provide exactly one target path; flags precede the path")
	}
	path, err := filepath.Abs(f.Arg(0))
	if err != nil {
		return err
	}
	switch args[0] {
	case "inspect":
		report, err := inspect.Analyze(path)
		if err != nil {
			return err
		}
		if *jsonMode {
			return emit(report)
		}
		fmt.Fprintf(out, "%s: %s, %d-bit, %s\nSHA256: %s\n", report.Path, report.Architecture, report.Bits, report.Type, report.SHA256)
		keys := []string{}
		for k := range report.Protections {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := report.Protections[k]
			fmt.Fprintf(out, "%-10s %-10s %s\n", k, v.Status, v.Evidence)
		}
	case "run":
		metadata, err := inspect.Analyze(path)
		if err != nil {
			return err
		}
		if !metadata.ExecutionSupported || metadata.Type == "ET_DYN" && metadata.Protections["pie"].Status == "unknown" {
			return errors.New("target is not a supported Linux x86/x64 executable")
		}
		var data []byte
		if *input != "" {
			data, err = runner.ReadInput(*input)
			if err != nil {
				return err
			}
		}
		report, err := runner.Run(ctx, runner.Request{Program: path, Input: data, Timeout: *timeout})
		if err != nil {
			return err
		}
		ex, err := extract.New(*pattern)
		if err != nil {
			return err
		}
		cands := ex.Find(report.Stdout, data, "stdout")
		cands = append(cands, ex.Find(report.Stderr, data, "stderr")...)
		flags := extract.Recovered(cands)
		if *jsonMode {
			if err = emit(runOutput{Result: report, RecoveredFlags: flags}); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(out, "outcome=%s exit=%d signal=%s duration=%dms truncated=%v\nstdout:\n%s\nstderr:\n%s\n", report.Outcome, report.ExitCode, report.Signal, report.DurationMS, report.OutputTruncated, report.Stdout, report.Stderr)
			if len(flags) > 0 {
				fmt.Fprintf(out, "recovered flags (not echoed from input): %v\n", flags)
			}
		}
		if report.Outcome != "exited" || report.ExitCode != 0 {
			return errors.New("target did not exit successfully; see recorded outcome")
		}
	case "detect":
		report, err := detect.Probe(ctx, path, *timeout)
		if err != nil {
			return err
		}
		if *jsonMode {
			return emit(report)
		}
		for _, finding := range report.Findings {
			fmt.Fprintf(out, "%s [%s]: %s\n", finding.Kind, finding.Status, finding.Evidence)
		}
		if len(report.Findings) == 0 {
			fmt.Fprintln(out, "No findings confirmed by the available probes.")
		}
		for _, attempt := range report.Attempts {
			fmt.Fprintf(out, "%s: %s, exit=%d\n", attempt.Name, attempt.Result.Outcome, attempt.Result.ExitCode)
		}
		for _, limitation := range report.Limitations {
			fmt.Fprintln(out, "Limitation:", limitation)
		}
	case "solve":
		report, err := solve.Solve(ctx, path, *pattern, *remote, *libc, *timeout)
		if err != nil {
			return err
		}
		if *jsonMode {
			if err = emit(report); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(out, "pattern: %s\n", report.Pattern)
			if report.Solved {
				fmt.Fprintf(out, "SOLVED: recovered %v\n", report.Flags)
				if report.Winning != nil {
					fmt.Fprintf(out, "strategy=%s reproducible payload=%q\n", report.Winning.Strategy, report.Winning.Payload)
				}
			} else {
				fmt.Fprintln(out, "NOT SOLVED: no non-echoed flag recovered by the available strategies")
			}
			for _, a := range report.Attempts {
				fmt.Fprintf(out, "  attempt %s: outcome=%s recovered=%v\n", a.Strategy, a.Result.Outcome, a.Recovered)
			}
			for _, limitation := range report.Limitations {
				fmt.Fprintln(out, "Limitation:", limitation)
			}
		}
		if !report.Solved {
			return errors.New("no flag recovered; see recorded attempts")
		}
	}
	return nil
}
