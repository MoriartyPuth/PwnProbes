// Package execution is the seam between exploitation strategies and the way a
// target is actually run. Strategies depend on the Executor and Session
// interfaces here instead of calling internal/runner and internal/session
// directly, so the backend can change (native subprocess, remote TCP, and later
// a sandbox, container, or SSH runner) without touching strategy code.
//
// This first step is a faithful facade: Native delegates to the existing runner
// and session packages and changes no behavior. Request and Result are aliases
// of the runner types so no conversion or data copy is introduced yet; neutral
// types can be substituted later without disturbing call sites.
package execution

import (
	"context"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/runner"
	"github.com/MoriartyPuth/PwnProbes/internal/session"
)

// Request is a single bounded one-shot execution. It aliases runner.Request so
// existing call sites and JSON shapes are unchanged.
type Request = runner.Request

// Result is the outcome of a one-shot execution. It aliases runner.Result.
type Result = runner.Result

// DefaultDialTimeout is used for a remote session when SessionRequest leaves
// DialTimeout unset, preserving the solver's previous 5s dial budget.
const DefaultDialTimeout = 5 * time.Second

// SessionRequest describes an interactive connection. When Remote is set it is a
// TCP dial to that host:port; otherwise it is a local subprocess started from
// Program with the given arguments, environment, and working directory.
type SessionRequest struct {
	Remote      string        // host:port; when non-empty, dial instead of spawn
	DialTimeout time.Duration // remote dial budget; DefaultDialTimeout when zero
	Program     string        // local subprocess path
	Args        []string
	Env         []string
	WorkDir     string
}

// Session is the interactive byte transport a strategy drives. It is the method
// set of *session.Conn, so that type satisfies this interface directly.
type Session interface {
	Send(b []byte) error
	SendLine(b []byte) error
	RecvUntil(delim []byte, timeout time.Duration) ([]byte, error)
	RecvUntilIdle(idle time.Duration) []byte
	Received() string
	Close() error
}

// Executor runs targets. Run performs a bounded one-shot execution; Open starts
// an interactive session. Both take a context so cancellation and deadlines
// propagate to the underlying process or socket.
type Executor interface {
	Run(ctx context.Context, req Request) (Result, error)
	Open(ctx context.Context, req SessionRequest) (Session, error)
}

// Native is the default Executor: a local subprocess for one-shot runs and
// sessions, and a TCP dial for remote sessions. It adds no isolation beyond what
// runner and session already provide.
type Native struct{}

// Run executes req as a bounded local subprocess via internal/runner.
func (Native) Run(ctx context.Context, req Request) (Result, error) {
	return runner.Run(ctx, req)
}

// Open starts an interactive session: a TCP dial when req.Remote is set,
// otherwise a local subprocess.
func (Native) Open(ctx context.Context, req SessionRequest) (Session, error) {
	if req.Remote != "" {
		timeout := req.DialTimeout
		if timeout == 0 {
			timeout = DefaultDialTimeout
		}
		conn, err := session.Dial(ctx, req.Remote, timeout)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	conn, err := session.Spawn(ctx, req.Program, req.Args, req.Env, req.WorkDir)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Compile-time guarantees: Native is an Executor, and *session.Conn is a Session.
var (
	_ Executor = Native{}
	_ Session  = (*session.Conn)(nil)
)
