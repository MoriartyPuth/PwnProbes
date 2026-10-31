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
	"strings"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/benchmark"
	"github.com/MoriartyPuth/PwnProbes/internal/detect"
	"github.com/MoriartyPuth/PwnProbes/internal/extract"
	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
	"github.com/MoriartyPuth/PwnProbes/internal/runner"
	"github.com/MoriartyPuth/PwnProbes/internal/solve"
)

const version = "0.5.0"

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
		return errors.New("usage: pwnprobe inspect|run|detect|analyze|plan|solve|auto|assisted|strategies|workspace|benchmark|version (use <command> -h)")
	}
	if args[0] == "version" {
		fmt.Fprintln(out, version)
		return nil
	}
	// `auto` is the roadmap's name for a full solve (auto + RecoverFlag); it is a
	// pure alias so it shares solve's flags, engine, and output exactly.
	if args[0] == "auto" {
		args[0] = "solve"
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(errOut)
	jsonMode := f.Bool("json", false, "emit structured JSON")
	timeout := f.Duration("timeout", time.Second, "per-run deadline (maximum 1 minute)")
	var input, manifest, original, baseline, pattern, remote, libc, save, verify *string
	var planOnly, redact, approve *bool
	switch args[0] {
	case "inspect", "detect", "strategies":
	case "analyze", "plan":
		remote = f.String("remote", "", "select remote-mode plans (host:port); the path argument is a local copy for static analysis")
	case "assisted":
		pattern = f.String("flag-pattern", "", "regexp for recovered flags; empty uses the default CTF shape")
		remote = f.String("remote", "", "exploit a remote host:port over TCP; the path argument is a local copy for analysis")
		libc = f.String("libc", "", "path to the target's libc for ret2libc offset resolution")
		save = f.String("save", "", "on --approve, save the run as a workspace JSON file at this path")
		redact = f.Bool("redact", false, "with --save, strip sensitive config")
		approve = f.Bool("approve", false, "execute the plan; without it, assisted only previews and does not run the target")
	case "workspace":
		verify = f.String("verify", "", "path to the current binary to check the workspace's identity against")
	case "run":
		input = f.String("input", "", "read stdin bytes from a file; otherwise send EOF")
		pattern = f.String("flag-pattern", "", "regexp for recovered flags; empty uses the default CTF shape")
	case "solve":
		pattern = f.String("flag-pattern", "", "regexp for recovered flags; empty uses the default CTF shape")
		remote = f.String("remote", "", "exploit a remote host:port over TCP; the path argument is a local copy for analysis")
		libc = f.String("libc", "", "path to the target's libc for ret2libc offset resolution (for a remote libc that differs from this machine's)")
		planOnly = f.Bool("plan-only", false, "show the candidate plans without executing the target")
		save = f.String("save", "", "save the run as a workspace JSON file at this path")
		redact = f.Bool("redact", false, "with --save, strip sensitive config (remote endpoint, libc path, absolute paths)")
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
	if args[0] == "strategies" {
		if f.NArg() != 0 {
			return errors.New("strategies lists the available strategies and takes no target")
		}
		catalog := solve.Catalog()
		if *jsonMode {
			return emit(catalog)
		}
		for _, st := range catalog {
			modes := make([]string, len(st.Modes))
			for i, m := range st.Modes {
				modes[i] = string(m)
			}
			plan := "exec-only"
			if st.Plannable {
				plan = "plannable"
			}
			fmt.Fprintf(out, "%-24s [%-13s] %-9s %-10s %s\n", st.ID, strings.Join(modes, ","), st.Cost, plan, st.Description)
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
	case "analyze":
		report, err := solve.PlanOnly(ctx, path, *remote, "")
		if err != nil {
			return err
		}
		if *jsonMode {
			return emit(report)
		}
		b := report.Binary
		fmt.Fprintf(out, "analyze %s: %s %d-bit %s\nSHA256: %s\n", b.Path, b.Architecture, b.Bits, b.Type, b.SHA256)
		if report.Context != nil {
			c := report.Context.Capabilities
			fmt.Fprintf(out, "capabilities: nx=%v pie=%v canary=%v full_relro=%v exec_supported=%v\n", c.NX, c.PIE, c.Canary, c.FullRELRO, c.ExecutionSupported)
		}
		fmt.Fprintf(out, "%d candidate plan(s) for %s mode (target not executed):\n", len(report.Plans), report.Environment.Mode)
		printPlans(out, report.Plans)
		for _, l := range report.Limitations {
			fmt.Fprintln(out, "Limitation:", l)
		}
		return nil
	case "plan":
		report, err := solve.PlanOnly(ctx, path, *remote, "")
		if err != nil {
			return err
		}
		if *jsonMode {
			return emit(report)
		}
		fmt.Fprintf(out, "%d candidate plan(s) for %s mode (target not executed):\n", len(report.Plans), report.Environment.Mode)
		printPlans(out, report.Plans)
		return nil
	case "assisted":
		prev, err := solve.PlanOnly(ctx, path, *remote, *libc)
		if err != nil {
			return err
		}
		if !*approve {
			if *jsonMode {
				return emit(prev)
			}
			fmt.Fprintln(out, "assisted mode — review before executing (nothing has run):")
			fmt.Fprintln(out, "objective: recover_flag (standard set also graded: leak/control/write/shell)")
			fmt.Fprintf(out, "execution policy: native %s execution\n", prev.Environment.Mode)
			printPlans(out, prev.Plans)
			for _, l := range prev.Limitations {
				fmt.Fprintln(out, "Limitation:", l)
			}
			fmt.Fprintln(out, "re-run with --approve to execute via the engine.")
			return nil
		}
		// Approved: run the same engine as `solve`, by re-dispatching with the
		// --approve flag removed so solve's flag set parses cleanly.
		var solveArgs []string
		for _, a := range args {
			switch a {
			case "--approve", "-approve", "--approve=true", "-approve=true":
				continue
			}
			solveArgs = append(solveArgs, a)
		}
		solveArgs[0] = "solve"
		fmt.Fprintln(errOut, "assisted: approved — executing via the engine.")
		return execute(ctx, solveArgs, out, errOut)
	case "workspace":
		w, err := solve.LoadWorkspace(path)
		if err != nil {
			return err
		}
		var vr *solve.VerifyResult
		if *verify != "" {
			binPath, aerr := filepath.Abs(*verify)
			if aerr != nil {
				return aerr
			}
			res, verr := w.VerifyPath(binPath)
			if verr != nil {
				return verr
			}
			vr = &res
		}
		if *jsonMode {
			if vr != nil {
				return emit(struct {
					Workspace solve.Workspace    `json:"workspace"`
					Verify    solve.VerifyResult `json:"verify"`
				}{w, *vr})
			}
			return emit(w)
		}
		fmt.Fprintf(out, "workspace schema=%s saved=%s\n", w.Version, w.SavedAt.Format("2006-01-02T15:04:05Z"))
		fmt.Fprintf(out, "target: %s sha256=%s %s %d-bit mode=%s\n", w.Target.Path, w.Target.SHA256, w.Target.Architecture, w.Target.Bits, w.Target.Mode)
		fmt.Fprintf(out, "solved=%v flags=%v\n", w.Solved, w.Flags)
		fmt.Fprintf(out, "findings=%d primitives=%d plans=%d attempts=%d objectives=%d\n", len(w.Findings), len(w.Primitives), len(w.Plans), len(w.Attempts), len(w.Objectives))
		for _, obj := range w.Objectives {
			if obj.Status != solve.StatusInconclusive {
				fmt.Fprintf(out, "  objective %-20s %s\n", obj.Objective, obj.Status)
			}
		}
		if vr != nil {
			if vr.Match {
				fmt.Fprintln(out, "identity: MATCH — the saved analysis still applies to this binary")
			} else {
				fmt.Fprintln(out, "identity: MISMATCH — saved addresses/plans may be invalid:")
				for _, c := range vr.Changes {
					fmt.Fprintln(out, "   -", c)
				}
			}
		}
		return nil
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
		if *planOnly {
			report, err := solve.PlanOnly(ctx, path, *remote, *libc)
			if err != nil {
				return err
			}
			if *jsonMode {
				return emit(report)
			}
			fmt.Fprintf(out, "plan-only: %d candidate plan(s) for %s mode (target not executed)\n", len(report.Plans), report.Environment.Mode)
			printPlans(out, report.Plans)
			for _, limitation := range report.Limitations {
				fmt.Fprintln(out, "Limitation:", limitation)
			}
			return nil
		}
		report, err := solve.Solve(ctx, path, *pattern, *remote, *libc, *timeout)
		if err != nil {
			return err
		}
		if *save != "" {
			w := solve.WorkspaceFromReport(&report)
			if *redact {
				w = w.Redacted()
			}
			if werr := w.Save(*save); werr != nil {
				return fmt.Errorf("save workspace: %w", werr)
			}
			fmt.Fprintf(errOut, "workspace saved to %s\n", *save)
		}
		if *jsonMode {
			if err = emit(report); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(out, "pattern: %s\n", report.Pattern)
			if len(report.Plan) > 0 {
				planned := make([]string, len(report.Plan))
				for i, p := range report.Plan {
					planned[i] = p.ID
					if p.Deferred {
						planned[i] += "*"
					}
				}
				fmt.Fprintf(out, "plan (* = deferred as expensive): %s\n", strings.Join(planned, " -> "))
			}
			printPlans(out, report.Plans)
			env := report.Environment
			commit := env.Commit
			if commit == "" {
				commit = "unknown"
			}
			fmt.Fprintf(out, "env: commit=%s go=%s %s/%s mode=%s budget=%dms\n", commit, env.GoVersion, env.OS, env.Arch, env.Mode, env.TimeoutMS)
			if report.Solved {
				fmt.Fprintf(out, "SOLVED: recovered %v\n", report.Flags)
				if report.Winning != nil {
					fmt.Fprintf(out, "strategy=%s reproducible payload=%q\n", report.Winning.Strategy, report.Winning.Payload)
				}
			} else {
				fmt.Fprintln(out, "NOT SOLVED: no non-echoed flag recovered by the available strategies")
			}
			if report.Verification != nil {
				fmt.Fprintf(out, "verification: objective=%s status=%s (%s)\n", report.Verification.Objective, report.Verification.Status, report.Verification.Detail)
			}
			for _, obj := range report.Objectives {
				// RecoverFlag is already shown on the verification line above; list
				// the other objectives that reached a rung beyond inconclusive.
				if obj.Objective == "recover_flag" || obj.Status == solve.StatusInconclusive {
					continue
				}
				fmt.Fprintf(out, "objective %-20s %s\n", obj.Objective, obj.Status)
			}
			if report.Context != nil {
				for _, f := range report.Context.Findings {
					line := fmt.Sprintf("finding %-14s status=%s source=%s", f.Kind, f.Status, f.Source)
					if f.Interpretation != "" {
						line += " interpretation=" + f.Interpretation
					}
					fmt.Fprintln(out, line)
				}
				for _, p := range report.Context.Primitives {
					where := string(p.Domain)
					if p.Target != "" {
						where = p.Target
					}
					fmt.Fprintf(out, "primitive %-8s %-8s status=%s source=%s evidence=%v\n", p.Kind, where, p.Status, p.Source, p.Evidence)
				}
			}
			for _, a := range report.Attempts {
				fmt.Fprintf(out, "  attempt %s: outcome=%s recovered=%v\n", a.Strategy, a.Result.Outcome, a.Recovered)
			}
			fmt.Fprintf(out, "timing: total=%dms\n", report.Timing.TotalMS)
			for _, st := range report.Timing.Strategies {
				fmt.Fprintf(out, "  %-24s %6dms  attempts=%d\n", st.Name, st.DurationMS, st.Attempts)
			}
			for _, rej := range report.Rejected {
				fmt.Fprintf(out, "rejected %-24s %s\n", rej.ID, rej.Reason)
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

// printPlans renders the inspectable candidate plans: one header line per plan
// (strategy, feasibility, risk) with any unmet requirement, then its steps.
func printPlans(out io.Writer, plans []solve.Plan) {
	for _, p := range plans {
		feas := "feasible"
		if !p.Feasible {
			feas = "INFEASIBLE"
		}
		fmt.Fprintf(out, "plan %-20s %-10s risk=%-6s cost=%s\n", p.Strategy, feas, p.Risk, p.Cost.Tier)
		for _, r := range p.Requires {
			if !r.Met {
				mark := "unmet: " + r.Name
				if r.Detail != "" {
					mark += " (" + r.Detail + ")"
				}
				fmt.Fprintln(out, "    requirement", mark)
			}
		}
		for _, st := range p.Steps {
			fmt.Fprintf(out, "    %d. %s\n", st.Index, st.Action)
		}
	}
}
