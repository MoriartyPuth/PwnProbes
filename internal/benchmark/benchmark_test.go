package benchmark

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Run must honour context cancellation: with an already-cancelled context it
// returns the cancellation error at the first case, before building anything
// with gcc (so the check is cross-platform and needs no toolchain).
func TestRunCancelled(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifest, []byte(`[{"name":"c","source":"c.c","format_string":false}]`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Run(ctx, manifest, "", "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run with cancelled context: err = %v, want context.Canceled", err)
	}
}

// A manifest with no cases is rejected rather than silently passing.
func TestRunRejectsEmptyManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifest, []byte(`[]`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := Run(context.Background(), manifest, "", ""); err == nil {
		t.Fatalf("expected an error for an empty manifest")
	}
}
