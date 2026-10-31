package solve

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/inspect"
)

// This file adds workspace persistence (roadmap §17): a round-trippable record of
// a run — target identity, the shared context (findings, primitives, knowledge),
// the plans, the attempts, and the objective verifications — so interactive and
// resumed work can pick up where a run left off. It is additive: Solve is
// unchanged, and a workspace is built from a finished Report.
//
// Three properties matter for safe resume (roadmap §28.3):
//   - identity: resuming against a different binary (or arch) is detected, since
//     addresses, primitives, and plans from one binary do not transfer to another;
//   - redaction: a workspace can be exported with sensitive configuration (remote
//     endpoint, libc path, absolute target path) stripped;
//   - bounded paths: artifact file names are validated so a workspace cannot be
//     made to write outside its directory.

// WorkspaceVersion is the schema version of a saved workspace. Load rejects a
// file whose major version differs, so an incompatible schema fails loudly
// rather than being half-read.
const WorkspaceVersion = "1.0"

// Workspace is the persisted state of a run (roadmap §17). It is a projection of
// a finished Report, serialized to JSON (target.pwnprobe.json by convention).
type Workspace struct {
	Version      string         `json:"version"`
	SavedAt      time.Time      `json:"saved_at"`
	Environment  Environment    `json:"environment"`
	Target       Target         `json:"target"`
	Binary       inspect.Report `json:"binary"`
	Capabilities Capabilities   `json:"capabilities"`
	Findings     []Finding      `json:"findings,omitempty"`
	Primitives   []Primitive    `json:"primitives,omitempty"`
	Knowledge    Knowledge      `json:"knowledge"`
	Plans        []Plan         `json:"plans,omitempty"`
	Attempts     []Attempt      `json:"attempts,omitempty"`
	Objectives   []Verification `json:"objectives,omitempty"`
	Solved       bool           `json:"solved"`
	Flags        []string       `json:"flags,omitempty"`
}

// WorkspaceFromReport builds a workspace from a finished report. It reads the
// shared context when present (it always is for a completed solve) and falls back
// to the report's own fields otherwise.
func WorkspaceFromReport(r *Report) Workspace {
	w := Workspace{
		Version:     WorkspaceVersion,
		SavedAt:     time.Now().UTC(),
		Environment: r.Environment,
		Binary:      r.Binary,
		Plans:       r.Plans,
		Attempts:    r.Attempts,
		Objectives:  r.Objectives,
		Solved:      r.Solved,
		Flags:       r.Flags,
	}
	if r.Context != nil {
		w.Target = r.Context.Target
		w.Capabilities = r.Context.Capabilities
		w.Findings = r.Context.Findings
		w.Primitives = r.Context.Primitives
		w.Knowledge = r.Context.Knowledge
		// Prefer the context's binary (identical to r.Binary, but it is the
		// authoritative copy the run reasoned over).
		w.Binary = r.Context.Binary
	}
	return w
}

// Save writes the workspace as indented JSON to path. The path's base name is
// validated (see checkArtifactName) so a stray or hostile name cannot escape its
// directory.
func (w Workspace) Save(path string) error {
	if err := checkArtifactName(filepath.Base(path)); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(blob, '\n'), 0o644)
}

// LoadWorkspace reads and validates a saved workspace. It rejects a file whose
// major schema version differs from WorkspaceVersion.
func LoadWorkspace(path string) (Workspace, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return Workspace{}, err
	}
	var w Workspace
	if err := json.Unmarshal(blob, &w); err != nil {
		return Workspace{}, fmt.Errorf("parse workspace: %w", err)
	}
	if major(w.Version) != major(WorkspaceVersion) {
		return Workspace{}, fmt.Errorf("incompatible workspace schema %q (this build reads %s.x)", w.Version, major(WorkspaceVersion))
	}
	return w, nil
}

// Redacted returns a copy of the workspace with sensitive configuration removed,
// for sharing an exported artifact (roadmap §28.3): the remote endpoint, the
// resolved libc path, and the absolute target path are stripped, leaving the
// analysis intact.
func (w Workspace) Redacted() Workspace {
	c := w
	c.Target.Remote = ""
	c.Target.Path = filepath.Base(c.Target.Path)
	c.Binary.Path = filepath.Base(c.Binary.Path)
	if c.Knowledge.Libc != nil {
		libc := *c.Knowledge.Libc
		if libc.Path != "" {
			libc.Path = filepath.Base(libc.Path)
		}
		c.Knowledge.Libc = &libc
	}
	return c
}

// VerifyResult is the outcome of checking a workspace against a current binary.
// Match is true only when nothing that would invalidate addresses or plans has
// changed; Changes lists what differs otherwise.
type VerifyResult struct {
	Match   bool     `json:"match"`
	Changes []string `json:"changes,omitempty"`
}

// VerifyAgainst checks whether this workspace still applies to the given current
// binary analysis. A changed SHA-256, architecture, or bit width invalidates the
// saved addresses, primitives, and plans and is reported.
func (w Workspace) VerifyAgainst(cur inspect.Report) VerifyResult {
	var changes []string
	if w.Target.SHA256 != "" && cur.SHA256 != w.Target.SHA256 {
		changes = append(changes, fmt.Sprintf("binary changed: sha256 %s -> %s", short(w.Target.SHA256), short(cur.SHA256)))
	}
	if w.Target.Architecture != "" && cur.Architecture != w.Target.Architecture {
		changes = append(changes, fmt.Sprintf("architecture changed: %s -> %s", w.Target.Architecture, cur.Architecture))
	}
	if w.Target.Bits != 0 && cur.Bits != w.Target.Bits {
		changes = append(changes, fmt.Sprintf("bit width changed: %d -> %d", w.Target.Bits, cur.Bits))
	}
	return VerifyResult{Match: len(changes) == 0, Changes: changes}
}

// VerifyPath analyzes the binary at path and verifies the workspace against it.
func (w Workspace) VerifyPath(path string) (VerifyResult, error) {
	cur, err := inspect.Analyze(path)
	if err != nil {
		return VerifyResult{}, err
	}
	return w.VerifyAgainst(cur), nil
}

// checkArtifactName rejects a name that could escape its directory or is
// unreasonable: empty, a path separator, a parent reference, or absurdly long.
// Artifact files are always written by base name inside a chosen directory.
func checkArtifactName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("invalid artifact name %q", name)
	}
	if len(name) > 255 {
		return fmt.Errorf("artifact name too long (%d bytes)", len(name))
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return fmt.Errorf("artifact name %q must not contain a path separator or %q", name, "..")
	}
	return nil
}

// SafeArtifactPath joins dir and name after validating name, so an attempt
// artifact (input, transcript) is always written inside dir and never escapes it.
func SafeArtifactPath(dir, name string) (string, error) {
	if err := checkArtifactName(name); err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// major returns the major component of a dotted version ("1.0" -> "1").
func major(v string) string {
	if i := strings.IndexByte(v, '.'); i >= 0 {
		return v[:i]
	}
	return v
}

// short abbreviates a hash for a human-readable change message.
func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
