package solve

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

// angrTimeout bounds the symbolic-execution subprocess. It also caps the cost of
// running angr against a non-logic (corruption) binary, where no legitimate path
// reaches the target.
const angrTimeout = 90 * time.Second

// angrHarness is a self-contained angr script: it loads the binary, finds blocks
// that reach a shell/flag (calls to system/execve or a win function), makes argv
// and stdin symbolic, explores to a target, and prints the solving argv and stdin
// as JSON. It is written to a temp file and run by a Python interpreter that has
// angr installed (PWNPROBE_PYTHON, else python3).
const angrHarness = `
import sys, json, logging
try:
    import angr
    try:
        import claripy
    except Exception:
        claripy = angr.claripy  # angr 10 bundles claripy as a submodule
except Exception as e:
    print(json.dumps({"ok": False, "reason": "angr import failed: %s" % e})); sys.exit(0)
for n in ("angr","cle","pyvex","claripy"):
    logging.getLogger(n).setLevel("ERROR")

NAMES = ("system","execve","execl","execlp","execvp","execvpe")
WINNAMES = ("win","print_flag","get_flag","getflag","give_flag","backdoor","shell")

def targets(proj):
    found = set()
    try:
        cfg = proj.analyses.CFGFast(normalize=True)
    except Exception:
        cfg = None
    wanted = {}
    for n in NAMES:
        s = proj.loader.find_symbol(n)
        if s is not None:
            wanted[s.rebased_addr] = n
    plt = getattr(proj.loader.main_object, "plt", {}) or {}
    for n, a in plt.items():
        if n in NAMES:
            wanted[a] = n
    if cfg is not None:
        for func in cfg.kb.functions.values():
            try:
                for site in func.get_call_sites():
                    if func.get_call_target(site) in wanted:
                        found.add(site)
            except Exception:
                pass
    for n in WINNAMES:
        s = proj.loader.find_symbol(n)
        if s is not None and getattr(s, "is_function", False):
            found.add(s.rebased_addr)
    return list(found)

def main():
    path = sys.argv[1]
    proj = angr.Project(path, auto_load_libs=False)
    tgts = targets(proj)
    if not tgts:
        print(json.dumps({"ok": False, "reason": "no system/execve/win target"})); return
    argv = [path]; syms = []
    for i in range(1, 4):
        a = claripy.BVS("arg%d" % i, 8 * 24); syms.append(a); argv.append(a)
    st = proj.factory.full_init_state(args=argv)
    for a in syms:
        for b in a.chop(8):
            st.solver.add(claripy.Or(b == 0, claripy.And(b >= 0x20, b <= 0x7e)))
    sm = proj.factory.simulation_manager(st)
    sm.explore(find=tgts, num_find=1)
    if not sm.found:
        print(json.dumps({"ok": False, "reason": "no path reached a target"})); return
    f = sm.found[0]
    try:
        stdin = f.posix.dumps(0)
    except Exception:
        stdin = b""
    out = []
    for a in syms:
        v = f.solver.eval(a, cast_to=bytes).split(b"\x00")[0]
        if v:
            out.append(v.decode("latin1"))
    print(json.dumps({"ok": True, "argv": out, "stdin_hex": stdin.hex(),
                      "targets": [hex(t) for t in tgts[:8]]}))

try:
    main()
except Exception as e:
    print(json.dumps({"ok": False, "reason": "error: %s" % e}))
`

type angrResult struct {
	OK       bool     `json:"ok"`
	Reason   string   `json:"reason"`
	Argv     []string `json:"argv"`
	StdinHex string   `json:"stdin_hex"`
}

func angrPython() string {
	if p := os.Getenv("PWNPROBE_PYTHON"); p != "" {
		return p
	}
	return "python3"
}

// angrStrategy solves a logic / argv / input-constraint challenge (not a memory
// corruption) by symbolic execution: it asks angr for an argv and stdin that
// reach a shell/flag block, then replays that input and keeps the flag only if it
// actually appears. It is local-only (replay controls argv) and skipped when the
// interpreter lacks angr.
func (s *solver) angrStrategy(ctx context.Context) (bool, error) {
	py := angrPython()
	if _, err := exec.LookPath(py); err != nil {
		return false, nil
	}

	harness, err := os.CreateTemp("", "pwnprobe-angr-*.py")
	if err != nil {
		return false, err
	}
	defer os.Remove(harness.Name())
	if _, err := harness.WriteString(angrHarness); err != nil {
		harness.Close()
		return false, err
	}
	harness.Close()

	runCtx, cancel := context.WithTimeout(ctx, angrTimeout)
	defer cancel()
	out, err := exec.CommandContext(runCtx, py, harness.Name(), s.path).Output()
	if err != nil {
		s.report.Limitations = append(s.report.Limitations, "symbolic execution (angr) unavailable or timed out; logic-puzzle strategy skipped")
		return false, nil
	}
	var res angrResult
	if jsonErr := json.Unmarshal(out, &res); jsonErr != nil || !res.OK {
		return false, nil
	}
	stdin, err := hex.DecodeString(res.StdinHex)
	if err != nil {
		return false, nil
	}

	// Verify by replaying the concrete input; only a genuinely printed flag counts.
	result, err := runner.Run(ctx, runner.Request{Program: s.path, Args: res.Argv, Input: stdin, Timeout: s.timeout, WorkDir: s.workDir})
	if err != nil {
		// e.g. a 32-bit target this host cannot execute; a replay failure is a
		// skip, not a solve error.
		s.report.Limitations = append(s.report.Limitations, "angr found an input but the local replay could not run the target")
		return false, nil
	}
	cands := s.ex.Find(result.Stdout, stdin, "stdout")
	cands = append(cands, s.ex.Find(result.Stderr, stdin, "stderr")...)
	note := "angr argv=" + shellJoin(res.Argv)
	return s.finalize("angr_logic", note, stdin, result, cands), nil
}

func shellJoin(a []string) string {
	out := ""
	for i, s := range a {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}
