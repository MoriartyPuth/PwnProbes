package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const MaxOutput = 1 << 20

type Request struct {
	Program string
	Args    []string
	Input   []byte
	Timeout time.Duration
	// WorkDir, when set, runs the target in this directory instead of a
	// disposable one, so resources beside the binary (such as a flag file) are
	// readable. This trades the disposable-directory isolation for the behavior
	// a local solver needs; HOME and TMPDIR still point at a scratch directory.
	WorkDir string
}
type Result struct {
	Outcome         string `json:"outcome"`
	ExitCode        int    `json:"exit_code"`
	Signal          string `json:"signal,omitempty"`
	DurationMS      int64  `json:"duration_ms"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	OutputTruncated bool   `json:"output_truncated"`
}
type bounded struct {
	mu        sync.Mutex
	data      bytes.Buffer
	truncated bool
}

func (b *bounded) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	left := MaxOutput - b.data.Len()
	if n > left {
		b.truncated = true
		p = p[:left]
	}
	_, _ = b.data.Write(p)
	return n, nil
}
func (b *bounded) snapshot() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String(), b.truncated
}

// Run uses a disposable working directory, bounded captured output, and a
// process-group deadline. It is NOT a security sandbox: the child has the
// caller's filesystem/network privileges and must be a trusted lab program.
func Run(ctx context.Context, req Request) (Result, error) {
	result := Result{ExitCode: -1}
	if runtime.GOOS != "linux" {
		return result, errors.New("execution requires Linux; on Windows use the Linux build in WSL")
	}
	if req.Timeout <= 0 || req.Timeout > time.Minute {
		return result, errors.New("timeout must be greater than zero and at most one minute")
	}
	if len(req.Input) > MaxOutput {
		return result, errors.New("input exceeds 1 MiB limit")
	}
	program, err := exec.LookPath(req.Program)
	if err != nil {
		return result, err
	}
	program, err = filepath.Abs(program)
	if err != nil {
		return result, err
	}
	dir, err := os.MkdirTemp("", "pwnprobe-run-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, req.Args...)
	cmd.Dir = dir
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + dir, "TMPDIR=" + dir}
	cmd.Stdin = bytes.NewReader(req.Input)
	out, errs := &bounded{}, &bounded{}
	cmd.Stdout = out
	cmd.Stderr = errs
	configure(cmd)
	cmd.WaitDelay = 250 * time.Millisecond
	start := time.Now()
	err = cmd.Run()
	result.DurationMS = time.Since(start).Milliseconds()
	if cmd.Process != nil {
		killGroup(cmd)
	}
	result.Stdout, result.OutputTruncated = out.snapshot()
	var truncated bool
	result.Stderr, truncated = errs.snapshot()
	result.OutputTruncated = result.OutputTruncated || truncated
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
		result.Signal = signal(cmd.ProcessState)
	}
	switch {
	case ctx.Err() != nil:
		result.Outcome = "timeout"
		if errors.Is(ctx.Err(), context.Canceled) {
			result.Outcome = "canceled"
		}
	case err == nil:
		result.Outcome = "exited"
	case errors.Is(err, exec.ErrWaitDelay):
		result.Outcome = "output_timeout"
	default:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return result, fmt.Errorf("start target: %w", err)
		}
		result.Outcome = "exited"
		if result.Signal != "" {
			result.Outcome = "crashed"
		}
	}
	return result, nil
}

func ReadInput(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxOutput+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxOutput {
		return nil, errors.New("input exceeds 1 MiB limit")
	}
	return b, nil
}
