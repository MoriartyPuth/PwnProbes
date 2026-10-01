// Package session provides an interactive byte transport that is the same for a
// local subprocess and a remote TCP service. It lets a strategy read output,
// including a leaked address, and send a response within one live connection -
// the capability one-shot execution cannot offer and the reason the leaked-
// address strategies need it (a leak is only valid in the run that produced it).
package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

// ErrTimeout is returned by RecvUntil when the delimiter does not arrive in time.
var ErrTimeout = errors.New("recv timeout")

// Conn is a bidirectional connection to a target. It is safe to call Send and
// the Recv family from one goroutine; a background reader pumps the underlying
// stream so reads can honor deadlines even on OS pipes.
type Conn struct {
	w      io.Writer
	closer io.Closer

	chunks chan []byte
	mu     sync.Mutex
	rerr   error

	leftover []byte
	received bytes.Buffer

	closeOnce sync.Once
}

func newConn(r io.Reader, w io.Writer, closer io.Closer) *Conn {
	c := &Conn{w: w, closer: closer, chunks: make(chan []byte, 32)}
	go c.pump(r)
	return c
}

func (c *Conn) pump(r io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			cp := make([]byte, n)
			copy(cp, buf[:n])
			c.chunks <- cp
		}
		if err != nil {
			c.mu.Lock()
			c.rerr = err
			c.mu.Unlock()
			close(c.chunks)
			return
		}
	}
}

// Send writes b to the target.
func (c *Conn) Send(b []byte) error {
	_, err := c.w.Write(b)
	return err
}

// SendLine writes b followed by a newline.
func (c *Conn) SendLine(b []byte) error {
	line := make([]byte, 0, len(b)+1)
	line = append(line, b...)
	line = append(line, '\n')
	return c.Send(line)
}

// RecvUntil reads until delim appears (returned inclusive) or timeout elapses.
// On end-of-stream it returns whatever remained with io.EOF.
func (c *Conn) RecvUntil(delim []byte, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for {
		if i := bytes.Index(c.leftover, delim); i >= 0 {
			end := i + len(delim)
			out := c.leftover[:end]
			c.leftover = c.leftover[end:]
			return out, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, ErrTimeout
		}
		timer := time.NewTimer(remaining)
		select {
		case chunk, ok := <-c.chunks:
			timer.Stop()
			if !ok {
				out := c.leftover
				c.leftover = nil
				c.mu.Lock()
				err := c.rerr
				c.mu.Unlock()
				if err == nil {
					err = io.EOF
				}
				return out, err
			}
			c.leftover = append(c.leftover, chunk...)
			c.received.Write(chunk)
		case <-timer.C:
			return nil, ErrTimeout
		}
	}
}

// RecvUntilIdle reads until no new data has arrived for idle, or end-of-stream.
// It is prompt-agnostic: an interactive target that stops to read input falls
// silent, so this reliably collects everything printed up to that point,
// including a leak printed before a blocking read.
func (c *Conn) RecvUntilIdle(idle time.Duration) []byte {
	out := c.leftover
	c.leftover = nil
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case chunk, ok := <-c.chunks:
			if !ok {
				return out
			}
			out = append(out, chunk...)
			c.received.Write(chunk)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(idle)
		case <-timer.C:
			return out
		}
	}
}

// Received returns everything read from the target so far.
func (c *Conn) Received() string { return c.received.String() }

// Close releases the connection and, for a subprocess, terminates it.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.closer != nil {
			err = c.closer.Close()
		}
	})
	return err
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// Dial opens a TCP connection to addr (host:port).
func Dial(ctx context.Context, addr string, timeout time.Duration) (*Conn, error) {
	d := net.Dialer{Timeout: timeout}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return newConn(nc, nc, nc), nil
}

// Spawn starts path as a child process and returns a connection to its stdin and
// merged stdout/stderr. env and dir control the child's environment and working
// directory; dir lets it read resources beside the binary, such as a flag file.
func Spawn(ctx context.Context, path string, args, env []string, dir string) (*Conn, error) {
	cctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cctx, path, args...)
	cmd.Dir = dir
	cmd.Env = env
	configureProc(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		cancel()
		return nil, err
	}
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		cancel()
		pw.Close()
		pr.Close()
		return nil, err
	}
	pw.Close() // parent drops its write end; the child keeps it until it exits
	go func() { _ = cmd.Wait() }()
	closer := closerFunc(func() error {
		cancel()
		_ = stdin.Close()
		return pr.Close()
	})
	return newConn(pr, stdin, closer), nil
}
