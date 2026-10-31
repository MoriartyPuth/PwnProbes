package solve

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
)

func sampleReport() *Report {
	tc := &TargetContext{
		Target:       Target{Path: "/abs/path/vuln", SHA256: "abc123def456", Architecture: "amd64", Bits: 64, Mode: "remote", Remote: "10.0.0.1:1337"},
		Binary:       inspect.Report{Path: "/abs/path/vuln", SHA256: "abc123def456", Architecture: "amd64", Bits: 64},
		Capabilities: Capabilities{NX: true, ExecutionSupported: true},
		Findings:     []Finding{{ID: "detect/format_string/0", Kind: FindingFormatString, Status: StatusConfirmed, Source: "detect"}},
		Knowledge:    Knowledge{Libc: &LibraryInfo{Path: "/usr/lib/libc.so.6", Source: "ldd", Resolved: true}},
	}
	tc.establishPrimitives()
	return &Report{
		Binary:     tc.Binary,
		Solved:     true,
		Flags:      []string{"FLAG{x}"},
		Context:    tc,
		Objectives: []Verification{{Objective: "recover_flag", Status: StatusObjectiveMet}},
		Attempts:   []Attempt{{Strategy: "stack_dump"}},
	}
}

// A workspace round-trips through Save/Load unchanged.
func TestWorkspaceRoundTrip(t *testing.T) {
	w := WorkspaceFromReport(sampleReport())
	dir := t.TempDir()
	path := filepath.Join(dir, "challenge.pwnprobe.json")
	if err := w.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadWorkspace(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Compare via canonical JSON so time/pointer fields compare by value.
	wantJSON, _ := json.Marshal(w)
	gotJSON, _ := json.Marshal(got)
	if string(wantJSON) != string(gotJSON) {
		t.Errorf("round-trip mismatch:\n want %s\n got  %s", wantJSON, gotJSON)
	}
	if got.Version != WorkspaceVersion || !got.Solved || len(got.Primitives) == 0 {
		t.Errorf("loaded workspace missing data: %+v", got)
	}
}

// Loading a workspace with an incompatible major schema version is rejected.
func TestWorkspaceSchemaMismatch(t *testing.T) {
	w := WorkspaceFromReport(sampleReport())
	w.Version = "2.0"
	dir := t.TempDir()
	path := filepath.Join(dir, "w.json")
	if err := w.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWorkspace(path); err == nil {
		t.Error("expected a schema-incompatibility error for version 2.0")
	}
}

// VerifyAgainst detects a changed binary (invalidating saved addresses/plans).
func TestWorkspaceVerifyIdentity(t *testing.T) {
	w := WorkspaceFromReport(sampleReport())

	same := inspect.Report{SHA256: "abc123def456", Architecture: "amd64", Bits: 64}
	if r := w.VerifyAgainst(same); !r.Match || len(r.Changes) != 0 {
		t.Errorf("same binary should match, got %+v", r)
	}

	changed := inspect.Report{SHA256: "ffffffffffff", Architecture: "amd64", Bits: 64}
	if r := w.VerifyAgainst(changed); r.Match || len(r.Changes) == 0 {
		t.Errorf("changed sha256 should mismatch, got %+v", r)
	}

	arch := inspect.Report{SHA256: "abc123def456", Architecture: "386", Bits: 32}
	r := w.VerifyAgainst(arch)
	if r.Match || len(r.Changes) < 2 {
		t.Errorf("changed arch+bits should report both, got %+v", r)
	}
}

// Redacted strips sensitive configuration while keeping the analysis.
func TestWorkspaceRedacted(t *testing.T) {
	r := WorkspaceFromReport(sampleReport()).Redacted()
	if r.Target.Remote != "" {
		t.Errorf("remote endpoint not redacted: %q", r.Target.Remote)
	}
	if r.Target.Path != "vuln" || r.Binary.Path != "vuln" {
		t.Errorf("absolute paths not reduced to basenames: target=%q binary=%q", r.Target.Path, r.Binary.Path)
	}
	if r.Knowledge.Libc == nil || r.Knowledge.Libc.Path != "libc.so.6" {
		t.Errorf("libc path not redacted: %+v", r.Knowledge.Libc)
	}
	// Analysis is preserved.
	if r.Target.SHA256 == "" || len(r.Findings) == 0 {
		t.Error("redaction should keep the analysis (sha256, findings)")
	}
}

// Artifact names that could escape their directory are rejected; safe ones join.
func TestSafeArtifactPath(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "a/b", "../escape", "x/../y", `a\b`} {
		if _, err := SafeArtifactPath("/base", bad); err == nil {
			t.Errorf("SafeArtifactPath should reject %q", bad)
		}
	}
	got, err := SafeArtifactPath("/base", "attempt-3.txt")
	if err != nil || got != filepath.Join("/base", "attempt-3.txt") {
		t.Errorf("SafeArtifactPath(/base, attempt-3.txt) = %q, %v", got, err)
	}
}

// Save rejects a destination whose base name is unsafe.
func TestWorkspaceSaveRejectsUnsafeName(t *testing.T) {
	w := WorkspaceFromReport(sampleReport())
	if err := w.Save(filepath.Join(t.TempDir(), "..")); err == nil {
		t.Error("Save should reject an unsafe base name")
	}
}
