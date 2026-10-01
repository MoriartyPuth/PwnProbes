package inspect

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

const MaxFileSize = 64 << 20

type Evidence struct {
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
}
type Symbol struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Size    uint64 `json:"size"`
}
type Report struct {
	Path               string              `json:"path"`
	SHA256             string              `json:"sha256"`
	Architecture       string              `json:"architecture"`
	Bits               int                 `json:"bits"`
	ByteOrder          string              `json:"byte_order"`
	Type               string              `json:"type"`
	Entry              string              `json:"entry"`
	ExecutionSupported bool                `json:"execution_supported"`
	Protections        map[string]Evidence `json:"protections"`
	Libraries          []string            `json:"libraries"`
	Imports            []string            `json:"imports"`
	Functions          []Symbol            `json:"functions"`
	Warnings           []string            `json:"warnings"`
}

// Analyze never runs the target or its loader. Canary evidence is binary-wide,
// not proof that any particular function is protected.
func Analyze(path string) (report Report, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("malformed ELF: %v", r)
		}
	}()
	file, err := os.Open(path)
	if err != nil {
		return report, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return report, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > MaxFileSize {
		return report, fmt.Errorf("target must be a regular file no larger than %d bytes", MaxFileSize)
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return report, err
	}
	f, err := elf.NewFile(file)
	if err != nil {
		return report, fmt.Errorf("read ELF: %w", err)
	}
	// Validate on-disk ranges before asking debug/elf to allocate section data.
	// This is a size guard, not a security boundary for hostile parser inputs.
	fileSize := uint64(stat.Size())
	var metadataBytes uint64
	for _, section := range f.Sections {
		if section.Type == elf.SHT_NOBITS {
			continue
		}
		if section.Offset > fileSize || section.FileSize > fileSize-section.Offset {
			return report, fmt.Errorf("section %q extends beyond the file", section.Name)
		}
		if section.Type == elf.SHT_SYMTAB || section.Type == elf.SHT_DYNSYM || section.Type == elf.SHT_STRTAB || section.Type == elf.SHT_DYNAMIC {
			if section.Flags&elf.SHF_COMPRESSED != 0 {
				return report, fmt.Errorf("compressed metadata section %q is unsupported", section.Name)
			}
			metadataBytes += section.Size
			if section.Size > MaxFileSize || metadataBytes > MaxFileSize {
				return report, fmt.Errorf("ELF metadata exceeds size budget")
			}
		}
	}
	for _, program := range f.Progs {
		if program.Off > fileSize || program.Filesz > fileSize-program.Off {
			return report, fmt.Errorf("program segment extends beyond the file")
		}
	}
	report = Report{Path: path, SHA256: hex.EncodeToString(hash.Sum(nil)), Type: f.Type.String(), Entry: fmt.Sprintf("0x%x", f.Entry), ByteOrder: f.Data.String(), Protections: map[string]Evidence{}, Libraries: []string{}, Imports: []string{}, Functions: []Symbol{}, Warnings: []string{}}
	if f.Class == elf.ELFCLASS64 {
		report.Bits = 64
	} else if f.Class == elf.ELFCLASS32 {
		report.Bits = 32
	}
	report.Architecture = f.Machine.String()
	switch f.Machine {
	case elf.EM_X86_64:
		report.Architecture = "amd64"
	case elf.EM_386:
		report.Architecture = "386"
	}
	report.ExecutionSupported = (f.Machine == elf.EM_X86_64 || f.Machine == elf.EM_386) && (f.Type == elf.ET_EXEC || f.Type == elf.ET_DYN) && f.Data == elf.ELFDATA2LSB
	unknown := Evidence{"unknown", "required metadata is absent"}
	report.Protections["nx"] = unknown
	report.Protections["pie"] = unknown
	relro, interpreter, rwx := false, false, false
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_GNU_STACK:
			if p.Flags&elf.PF_X != 0 {
				report.Protections["nx"] = Evidence{"disabled", "PT_GNU_STACK requests execution"}
			} else {
				report.Protections["nx"] = Evidence{"enabled", "PT_GNU_STACK does not request execution"}
			}
		case elf.PT_GNU_RELRO:
			relro = true
		case elf.PT_INTERP:
			interpreter = true
		}
		if p.Type == elf.PT_LOAD && p.Flags&(elf.PF_R|elf.PF_W|elf.PF_X) == elf.PF_R|elf.PF_W|elf.PF_X {
			rwx = true
		}
	}
	now, pieFlag := false, false
	for _, tag := range []elf.DynTag{elf.DT_BIND_NOW, elf.DT_FLAGS, elf.DT_FLAGS_1} {
		values, dynErr := f.DynValue(tag)
		if dynErr != nil {
			return report, fmt.Errorf("read dynamic tags: %w", dynErr)
		}
		for _, v := range values {
			if tag == elf.DT_BIND_NOW || tag == elf.DT_FLAGS && v&8 != 0 || tag == elf.DT_FLAGS_1 && v&1 != 0 {
				now = true
			}
			if tag == elf.DT_FLAGS_1 && v&0x08000000 != 0 {
				pieFlag = true
			}
		}
	}
	if f.Type == elf.ET_EXEC {
		report.Protections["pie"] = Evidence{"disabled", "ELF type is ET_EXEC"}
	} else if f.Type == elf.ET_DYN && (interpreter || pieFlag) {
		report.Protections["pie"] = Evidence{"enabled", "ET_DYN executable with interpreter or DF_1_PIE"}
	}
	if !relro {
		report.Protections["relro"] = Evidence{"none", "no PT_GNU_RELRO segment"}
	} else if now {
		report.Protections["relro"] = Evidence{"full", "PT_GNU_RELRO and immediate binding"}
	} else {
		report.Protections["relro"] = Evidence{"partial", "PT_GNU_RELRO without immediate binding"}
	}
	if rwx {
		report.Protections["rwx"] = Evidence{"present", "a PT_LOAD segment is readable, writable and executable"}
	} else {
		report.Protections["rwx"] = Evidence{"absent", "no RWX PT_LOAD segment found"}
	}
	if f.Section(".symtab") == nil {
		report.Protections["stripped"] = Evidence{"yes", "no .symtab section"}
	} else {
		report.Protections["stripped"] = Evidence{"no", ".symtab section present"}
	}
	report.Protections["canary"] = Evidence{"unknown", "no stack-check symbol found; this does not prove absence"}
	syms, symErr := f.Symbols()
	if symErr != nil && !errors.Is(symErr, elf.ErrNoSymbols) {
		return report, fmt.Errorf("read symbols: %w", symErr)
	}
	dyn, dynErr := f.DynamicSymbols()
	if dynErr != nil && !errors.Is(dynErr, elf.ErrNoSymbols) {
		return report, fmt.Errorf("read dynamic symbols: %w", dynErr)
	}
	seenFunctions, seenImports := map[string]bool{}, map[string]bool{}
	for _, s := range append(syms, dyn...) {
		if s.Name == "__stack_chk_fail" || s.Name == "__stack_chk_fail_local" {
			report.Protections["canary"] = Evidence{"present", "stack-check symbol found; coverage of individual functions is unknown"}
		}
		if s.Section == elf.SHN_UNDEF && s.Name != "" && !seenImports[s.Name] {
			report.Imports = append(report.Imports, s.Name)
			seenImports[s.Name] = true
		}
		if s.Section != elf.SHN_UNDEF && elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Name != "" && !seenFunctions[s.Name] {
			report.Functions = append(report.Functions, Symbol{s.Name, fmt.Sprintf("0x%x", s.Value), s.Size})
			seenFunctions[s.Name] = true
		}
	}
	libs, libErr := f.ImportedLibraries()
	if libErr != nil {
		return report, fmt.Errorf("read libraries: %w", libErr)
	}
	if libs != nil {
		report.Libraries = libs
	}
	sort.Strings(report.Imports)
	sort.Strings(report.Libraries)
	sort.Slice(report.Functions, func(i, j int) bool { return report.Functions[i].Name < report.Functions[j].Name })
	if !report.ExecutionSupported {
		report.Warnings = append(report.Warnings, "execution probes support little-endian Linux x86/x64 executables only")
	}
	report.Warnings = append(report.Warnings, "metadata describes binary properties, not confirmed vulnerabilities")
	return report, nil
}
