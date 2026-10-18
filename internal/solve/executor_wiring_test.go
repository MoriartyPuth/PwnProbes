package solve

import (
	"context"
	"testing"
	"time"

	"github.com/MoriartyPuth/PwnProbes/internal/execution"
	"github.com/MoriartyPuth/PwnProbes/internal/extract"
)

// fakeExecutor records calls and returns canned results, so the solver's routing
// through the Executor facade can be verified without running a real target.
type fakeExecutor struct {
	runCalls  int
	lastRun   execution.Request
	runResult execution.Result
}

func (f *fakeExecutor) Run(_ context.Context, req execution.Request) (execution.Result, error) {
	f.runCalls++
	f.lastRun = req
	return f.runResult, nil
}

func (f *fakeExecutor) Open(context.Context, execution.SessionRequest) (execution.Session, error) {
	return nil, nil
}

// TestAttemptRoutesThroughExecutor checks that a one-shot attempt goes through
// s.exec (not runner directly), forwards the request fields, and feeds the
// executor's result into flag extraction and finalize.
func TestAttemptRoutesThroughExecutor(t *testing.T) {
	ex, err := extract.New("")
	if err != nil {
		t.Fatalf("extractor: %v", err)
	}
	fe := &fakeExecutor{runResult: execution.Result{Outcome: "exited", Stdout: "flag{routed}"}}
	rep := &Report{}
	s := &solver{ex: ex, path: "/tmp/target", workDir: "/tmp", timeout: 2 * time.Second, report: rep, exec: fe}

	done, err := s.attempt(context.Background(), "probe", "", []byte("input"), false)
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	if fe.runCalls != 1 {
		t.Fatalf("executor Run called %d times, want 1", fe.runCalls)
	}
	if fe.lastRun.Program != "/tmp/target" || fe.lastRun.WorkDir != "/tmp" {
		t.Fatalf("forwarded request = %+v, want program/workdir from solver", fe.lastRun)
	}
	if string(fe.lastRun.Input) != "input" {
		t.Fatalf("forwarded input = %q, want %q", fe.lastRun.Input, "input")
	}
	if !done || !rep.Solved {
		t.Fatalf("expected the executor's stdout flag to be recovered (done=%v solved=%v)", done, rep.Solved)
	}
}
