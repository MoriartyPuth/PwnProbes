package execution

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"
)

// catPath returns a usable /bin/cat or skips. These tests exercise the native
// backend, which actually runs a target; internal/runner only executes on Linux,
// so they skip elsewhere (keeping the suite platform-independent off Linux) and
// skip on a host lacking /bin/cat.
func catPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("native target execution is Linux-only; GOOS=%s", runtime.GOOS)
	}
	const p = "/bin/cat"
	if _, err := os.Stat(p); err != nil {
		t.Skipf("%s not available: %v", p, err)
	}
	return p
}

// TestNativeRunOneShot checks the one-shot path: cat echoes its stdin and exits
// cleanly through the facade.
func TestNativeRunOneShot(t *testing.T) {
	cat := catPath(t)
	var ex Native
	res, err := ex.Run(context.Background(), Request{Program: cat, Input: []byte("hello\n"), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Outcome != "exited" || res.ExitCode != 0 {
		t.Fatalf("outcome=%q exit=%d, want exited/0", res.Outcome, res.ExitCode)
	}
	if res.Stdout != "hello\n" {
		t.Fatalf("stdout=%q, want %q", res.Stdout, "hello\n")
	}
}

// TestNativeOpenLocalSession round-trips a line through a local subprocess
// session opened via the facade.
func TestNativeOpenLocalSession(t *testing.T) {
	cat := catPath(t)
	var ex Native
	conn, err := ex.Open(context.Background(), SessionRequest{Program: cat})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()

	if err := conn.SendLine([]byte("ping")); err != nil {
		t.Fatalf("SendLine: %v", err)
	}
	out, err := conn.RecvUntil([]byte("\n"), 5*time.Second)
	if err != nil {
		t.Fatalf("RecvUntil: %v", err)
	}
	if string(out) != "ping\n" {
		t.Fatalf("recv=%q, want %q", out, "ping\n")
	}
}

// TestNativeOpenCancellation confirms cancellation propagates through the facade
// to a blocked session read: cat waits for more input, and cancelling the
// context unblocks RecvUntil well before its own timeout.
func TestNativeOpenCancellation(t *testing.T) {
	cat := catPath(t)
	ctx, cancel := context.WithCancel(context.Background())
	var ex Native
	conn, err := ex.Open(ctx, SessionRequest{Program: cat})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer conn.Close()

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err = conn.RecvUntil([]byte("\n"), 10*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("RecvUntil took %v; cancellation did not propagate promptly", elapsed)
	}
}
