// Package repl is the interactive frontend (roadmap §22). It is presentation and
// session state only: every analysis, planning, execution, workspace, and
// verification action goes through the engine services (solve.PlanOnly,
// solve.Solve, solve.Workspace), never a re-implementation of strategy logic.
// The shell supports partial progress — establishing a leak or demonstrating
// control is shown even when no flag is recovered — and treats a change to
// injected knowledge as invalidating the current plans.
package repl

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/solve"
)

// Engine is the set of engine services the shell drives. The real implementation
// wraps a target; a test can substitute a fake. It is deliberately small: the
// shell composes these, it does not contain exploitation logic.
type Engine interface {
	// Analyze runs static analysis and planning without executing the target.
	Analyze(context.Context) (solve.Report, error)
	// Solve runs the full engine against the target.
	Solve(context.Context) (solve.Report, error)
	// SetLibc injects a known libc path (knowledge) used by later runs.
	SetLibc(string)
	// Libc reports the currently injected libc path.
	Libc() string
}

// nativeEngine is the production engine: it drives the real solve services.
type nativeEngine struct {
	path, remote, libc string
	timeout            time.Duration
}

// NewEngine builds the production engine for a target.
func NewEngine(path, remote, libc string, timeout time.Duration) Engine {
	return &nativeEngine{path: path, remote: remote, libc: libc, timeout: timeout}
}

func (e *nativeEngine) Analyze(ctx context.Context) (solve.Report, error) {
	return solve.PlanOnly(ctx, e.path, e.remote, e.libc)
}

func (e *nativeEngine) Solve(ctx context.Context) (solve.Report, error) {
	return solve.Solve(ctx, e.path, "", e.remote, e.libc, e.timeout)
}

func (e *nativeEngine) SetLibc(p string) { e.libc = p }
func (e *nativeEngine) Libc() string     { return e.libc }

// shell holds the interactive session state.
type shell struct {
	eng    Engine
	out    io.Writer
	report *solve.Report    // last analyze/solve result
	ws     *solve.Workspace // last opened workspace
	stale  bool             // injected knowledge changed since the last analyze
}

// Run starts the read-eval-print loop, reading commands from in and writing to
// out, until EOF or a quit command. It returns any scanner error.
func Run(ctx context.Context, in io.Reader, out io.Writer, eng Engine) error {
	s := &shell{eng: eng, out: out}
	fmt.Fprintln(out, "pwnprobe interactive — 'help' for commands, 'quit' to exit")
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for {
		fmt.Fprint(out, "pwnprobe> ")
		if !sc.Scan() {
			break
		}
		if !s.dispatch(ctx, strings.TrimSpace(sc.Text())) {
			break
		}
	}
	fmt.Fprintln(out)
	return sc.Err()
}

// dispatch runs one command line; it returns false to end the loop.
func (s *shell) dispatch(ctx context.Context, line string) bool {
	if line == "" {
		return true
	}
	fields := strings.Fields(line)
	cmd, args := fields[0], fields[1:]
	switch cmd {
	case "help", "?":
		s.help()
	case "quit", "exit":
		return false
	case "info", "target":
		s.info(ctx)
	case "analyze":
		s.analyze(ctx)
	case "plans":
		s.plans(ctx)
	case "plan":
		s.plan(ctx, args)
	case "strategies":
		s.strategies()
	case "solve", "execute", "run":
		s.solve(ctx)
	case "findings":
		s.findings()
	case "primitives":
		s.primitives()
	case "objectives":
		s.objectives()
	case "knowledge":
		s.knowledge(args)
	case "save":
		s.save(args)
	case "open", "resume":
		s.open(args)
	default:
		fmt.Fprintf(s.out, "unknown command %q; type 'help'\n", cmd)
	}
	return true
}

func (s *shell) help() {
	fmt.Fprint(s.out, `commands:
  info                 target identity and capabilities
  analyze              static analysis + candidate plans (no execution)
  plans                list candidate plans
  plan <id|index>      inspect one plan's steps and requirements
  strategies           list available strategies
  solve                run the engine against the target
  findings             evidence findings from the last run
  primitives           established primitives from the last run
  objectives           objective verification from the last run
  knowledge            show injected knowledge
  knowledge libc PATH  inject a known libc (invalidates current plans)
  save FILE            save the last run as a workspace
  open FILE            resume a saved workspace
  quit                 exit
`)
}

// ensureAnalyzed makes sure a report exists and is not stale, re-analyzing when
// injected knowledge changed since the last analysis (roadmap §22: a knowledge
// change invalidates dependent plans rather than reusing stale ones).
func (s *shell) ensureAnalyzed(ctx context.Context) bool {
	if s.report != nil && !s.stale {
		return true
	}
	if s.stale && s.report != nil {
		fmt.Fprintln(s.out, "(knowledge changed; recomputing plans)")
	}
	rep, err := s.eng.Analyze(ctx)
	if err != nil {
		fmt.Fprintln(s.out, "analyze error:", err)
		return false
	}
	s.report = &rep
	s.stale = false
	return true
}

func (s *shell) info(ctx context.Context) {
	if !s.ensureAnalyzed(ctx) {
		return
	}
	t := s.report.Context.Target
	c := s.report.Context.Capabilities
	fmt.Fprintf(s.out, "target: %s\n  sha256=%s %s %d-bit mode=%s\n", t.Path, t.SHA256, t.Architecture, t.Bits, t.Mode)
	fmt.Fprintf(s.out, "  capabilities: nx=%v pie=%v canary=%v full_relro=%v exec=%v\n", c.NX, c.PIE, c.Canary, c.FullRELRO, c.ExecutionSupported)
	if libc := s.eng.Libc(); libc != "" {
		fmt.Fprintf(s.out, "  injected libc: %s\n", libc)
	}
}

func (s *shell) analyze(ctx context.Context) {
	s.stale = true // force a fresh analysis
	if !s.ensureAnalyzed(ctx) {
		return
	}
	fmt.Fprintf(s.out, "analyzed: %d candidate plan(s) (target not executed)\n", len(s.report.Plans))
}

func (s *shell) plans(ctx context.Context) {
	if !s.ensureAnalyzed(ctx) {
		return
	}
	if len(s.report.Plans) == 0 {
		fmt.Fprintln(s.out, "no candidate plans")
		return
	}
	for i, p := range s.report.Plans {
		feas := "feasible"
		if !p.Feasible {
			feas = "INFEASIBLE"
		}
		fmt.Fprintf(s.out, "[%d] %-20s %-10s risk=%-6s cost=%s\n", i, p.Strategy, feas, p.Risk, p.Cost.Tier)
	}
}

func (s *shell) plan(ctx context.Context, args []string) {
	if !s.ensureAnalyzed(ctx) {
		return
	}
	if len(args) == 0 {
		fmt.Fprintln(s.out, "usage: plan <id|index>")
		return
	}
	p, ok := s.findPlan(args[0])
	if !ok {
		fmt.Fprintf(s.out, "no plan %q (see 'plans')\n", args[0])
		return
	}
	feas := "feasible"
	if !p.Feasible {
		feas = "INFEASIBLE"
	}
	fmt.Fprintf(s.out, "%s: %s risk=%s cost=%s\n", p.Strategy, feas, p.Risk, p.Cost.Tier)
	for _, r := range p.Requires {
		mark := "met"
		if !r.Met {
			mark = "UNMET"
		}
		fmt.Fprintf(s.out, "  requirement [%s] %s\n", mark, r.Name)
	}
	for _, st := range p.Steps {
		fmt.Fprintf(s.out, "  %d. %s\n", st.Index, st.Action)
	}
	if len(p.Produces) > 0 {
		fmt.Fprintf(s.out, "  produces: %v\n", p.Produces)
	}
}

// findPlan resolves a plan by strategy id or by numeric index.
func (s *shell) findPlan(key string) (solve.Plan, bool) {
	if idx, err := strconv.Atoi(key); err == nil {
		if idx >= 0 && idx < len(s.report.Plans) {
			return s.report.Plans[idx], true
		}
		return solve.Plan{}, false
	}
	for _, p := range s.report.Plans {
		if p.Strategy == key {
			return p, true
		}
	}
	return solve.Plan{}, false
}

func (s *shell) strategies() {
	for _, st := range solve.Catalog() {
		plan := "exec-only"
		if st.Plannable {
			plan = "plannable"
		}
		fmt.Fprintf(s.out, "%-24s %-9s %s\n", st.ID, plan, st.Cost)
	}
}

func (s *shell) solve(ctx context.Context) {
	rep, err := s.eng.Solve(ctx)
	if err != nil {
		fmt.Fprintln(s.out, "solve error:", err)
		return
	}
	s.report = &rep
	s.stale = false
	if rep.Solved {
		fmt.Fprintf(s.out, "SOLVED: %v\n", rep.Flags)
	} else {
		fmt.Fprintln(s.out, "not solved — partial progress may still be useful (see 'objectives')")
	}
	s.objectives()
}

func (s *shell) findings() {
	if s.report == nil || s.report.Context == nil {
		fmt.Fprintln(s.out, "no findings yet (run 'solve' or 'analyze')")
		return
	}
	if len(s.report.Context.Findings) == 0 {
		fmt.Fprintln(s.out, "no findings")
		return
	}
	for _, f := range s.report.Context.Findings {
		fmt.Fprintf(s.out, "%-14s status=%s source=%s\n", f.Kind, f.Status, f.Source)
	}
}

func (s *shell) primitives() {
	if s.report == nil || s.report.Context == nil || len(s.report.Context.Primitives) == 0 {
		fmt.Fprintln(s.out, "no primitives established yet")
		return
	}
	for _, p := range s.report.Context.Primitives {
		fmt.Fprintf(s.out, "%-8s domain=%s status=%s source=%s\n", p.Kind, p.Domain, p.Status, p.Source)
	}
}

func (s *shell) objectives() {
	if s.report == nil || len(s.report.Objectives) == 0 {
		fmt.Fprintln(s.out, "no objective evidence yet (run 'solve')")
		return
	}
	for _, o := range s.report.Objectives {
		fmt.Fprintf(s.out, "%-20s %s\n", o.Objective, o.Status)
	}
}

func (s *shell) knowledge(args []string) {
	if len(args) == 0 {
		libc := s.eng.Libc()
		if libc == "" {
			libc = "(none)"
		}
		fmt.Fprintf(s.out, "injected libc: %s\n", libc)
		return
	}
	if args[0] == "libc" && len(args) >= 2 {
		s.eng.SetLibc(args[1])
		s.stale = true // invalidate dependent plans
		fmt.Fprintf(s.out, "libc set to %s; plans invalidated\n", args[1])
		return
	}
	fmt.Fprintln(s.out, "usage: knowledge [libc PATH]")
}

func (s *shell) save(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(s.out, "usage: save FILE")
		return
	}
	if s.report == nil {
		fmt.Fprintln(s.out, "nothing to save yet (run 'analyze' or 'solve')")
		return
	}
	w := solve.WorkspaceFromReport(s.report)
	if err := w.Save(args[0]); err != nil {
		fmt.Fprintln(s.out, "save error:", err)
		return
	}
	fmt.Fprintf(s.out, "workspace saved to %s\n", args[0])
}

func (s *shell) open(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(s.out, "usage: open FILE")
		return
	}
	w, err := solve.LoadWorkspace(args[0])
	if err != nil {
		fmt.Fprintln(s.out, "open error:", err)
		return
	}
	s.ws = &w
	fmt.Fprintf(s.out, "resumed workspace: %s sha256=%s solved=%v\n", w.Target.Path, w.Target.SHA256, w.Solved)
	fmt.Fprintf(s.out, "  findings=%d primitives=%d plans=%d objectives=%d\n", len(w.Findings), len(w.Primitives), len(w.Plans), len(w.Objectives))
}
