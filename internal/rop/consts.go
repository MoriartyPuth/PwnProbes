package rop

import "encoding/binary"

// HarvestConstants scans executable bytes for immediate values usable as call
// arguments: `movabs reg, imm64` (REX.W/REX.WB `48/49 B8+rd` + 8 bytes) and
// `mov reg32, imm32` (`B8+rd` + 4 bytes). It returns each distinct value with its
// occurrence count -- a magic argument a check compares against is typically a
// movabs immediate that repeats, so callers can rank by size and frequency.
func HarvestConstants(secs []Section) map[uint64]int {
	out := map[uint64]int{}
	for _, s := range secs {
		d := s.Data
		for i := 0; i < len(d); i++ {
			// movabs reg, imm64
			if (d[i] == 0x48 || d[i] == 0x49) && i+10 <= len(d) && d[i+1] >= 0xb8 && d[i+1] <= 0xbf {
				out[binary.LittleEndian.Uint64(d[i+2:i+10])]++
				i += 9
				continue
			}
			// mov reg32, imm32 (zero-extended)
			if d[i] >= 0xb8 && d[i] <= 0xbf && i+5 <= len(d) {
				out[uint64(binary.LittleEndian.Uint32(d[i+1:i+5]))]++
				i += 4
				continue
			}
		}
	}
	return out
}
