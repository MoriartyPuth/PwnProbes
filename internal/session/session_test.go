package session

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// infiniteReader always returns data and never blocks or errors, modelling a
// target that floods output faster than any consumer drains it.
type infiniteReader struct{}

func (infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

// countingCloser records whether Close was invoked.
type countingCloser struct{ closed int }

func (c *countingCloser) Close() error { c.closed++; return nil }

// TestCloseUnblocksStalledPump reproduces the documented deadlock: the target
// produces output without bound, the consumer never reads, the buffered channel
// fills, and the pump parks on a channel send. Close must still return promptly
// and reap the pump goroutine (via wg.Wait). Before the fix the pump had no way
// to observe cancellation on the send, so it leaked and Close could not join it.
func TestCloseUnblocksStalledPump(t *testing.T) {
	closer := &countingCloser{}
	c := newConn(context.Background(), infiniteReader{}, io.Discard, closer)

	// Wait until the pump has filled the buffered channel and is parked on send.
	deadline := time.Now().Add(2 * time.Second)
	for len(c.chunks) < cap(c.chunks) {
		if time.Now().After(deadline) {
			t.Fatalf("pump never filled the chunk buffer (len=%d, cap=%d)", len(c.chunks), cap(c.chunks))
		}
		time.Sleep(time.Millisecond)
	}

	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return: pump goroutine leaked on a full channel")
	}
	if closer.closed != 1 {
		t.Fatalf("underlying closer invoked %d times, want 1", closer.closed)
	}
}

// TestCloseIdempotent verifies repeated Close calls act once and stay bounded.
func TestCloseIdempotent(t *testing.T) {
	closer := &countingCloser{}
	c := newConn(context.Background(), infiniteReader{}, io.Discard, closer)

	for i := 0; i < 3; i++ {
		done := make(chan error, 1)
		go func() { done <- c.Close() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("Close call %d did not return", i)
		}
	}
	if closer.closed != 1 {
		t.Fatalf("underlying closer invoked %d times across repeated Close, want 1", closer.closed)
	}
}

// eofReader returns one chunk then end-of-stream, exercising the normal exit
// path where the pump closes the channel and RecvUntil surfaces io.EOF.
type eofReader struct{ sent bool }

func (r *eofReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, io.EOF
	}
	r.sent = true
	n := copy(p, []byte("hello\n"))
	return n, nil
}

func TestRecvUntilThenEOF(t *testing.T) {
	c := newConn(context.Background(), &eofReader{}, io.Discard, &countingCloser{})

	out, err := c.RecvUntil([]byte("\n"), time.Second)
	if err != nil {
		t.Fatalf("RecvUntil delimiter: %v", err)
	}
	if string(out) != "hello\n" {
		t.Fatalf("got %q, want %q", out, "hello\n")
	}

	// Next read drains the stream and reports EOF; Close stays bounded.
	if _, err := c.RecvUntil([]byte("X"), time.Second); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF after stream end, got %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return after EOF")
	}
}

// TestContextCancelUnblocksRecv ensures a blocked RecvUntil returns when the
// parent context is cancelled, confirming cancellation still propagates through
// the connection's derived context.
func TestContextCancelUnblocksRecv(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	// A reader that blocks forever: no data ever arrives. The closer closes the
	// pipe reader, as the real transports close their underlying net.Conn/os.Pipe
	// so a pump parked in Read unblocks on Close.
	pr, pw := io.Pipe()
	defer pw.Close()
	c := newConn(ctx, pr, io.Discard, pr)

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, err := c.RecvUntil([]byte("\n"), 3*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return after context cancel")
	}
}
