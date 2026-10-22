# Hybrid-framework roadmap — status

Tracks progress implementing the PwnProbes hybrid-framework roadmap (a shared
engine for auto / assisted / interactive binary-exploitation research while
retaining the existing solver). The roadmap defines a 15-PR sequence; this file
records what has landed and what is next.

Baseline before this work: `main` @ `78da9f5`.

## Done (6 of 15), all merged into `main`

| PR | Branch | Summary |
|----|--------|---------|
| 1 | `fix/session-pump-cancellation` | `internal/session` pump send is cancellation-aware; `Conn` owns a cancel func + `WaitGroup`; `Close()` is a bounded shutdown. |
| 2 | `feat/baseline-timing-instrumentation` | Solve report gains an `Environment` block (commit/go/os/arch/mode/budget) and per-strategy `Timing`; strategies are named and routed through one timing path. |
| 3 | `feat/executor-facade` | `internal/execution` adds `Executor`/`Session` interfaces + a `Native` adapter over runner+session; the solver runs through an injected executor. `Request`/`Result` alias the runner types. |
| 4 | `feat/strategy-interface` | `Strategy` interface (`ID`/`Description`/`Supports`/`Cost`/`Run`) + legacy wrappers; `Catalog()` and a `pwnprobe strategies` command. |
| 5 | `feat/strategy-registry` | One `registry` both modes query, replacing the two per-mode lists; `Supports`/`SupportResult` capability filtering with explained rejections (`rejected_strategies` in the report). |
| 6 | `feat/planner-ranking` | `CostEstimate` + `Cost()`; `registry.eligible` ranks deterministically — historical mode order kept, expensive strategies (angr, cross-run/session brute force) stably deferred, so `rop_planner` precedes `angr`. Global deadline enforced between strategies; report `plan`; cost tiers in `strategies`. |

Each PR is behavior-preserving except PR 6, which intentionally changes strategy
ordering (correctness preserved; the flag oracle and per-strategy gating are
unchanged).

## Next

- **PR 7 — TargetContext, evidence, and knowledge.** Introduce a central
  `TargetContext`; structured `Finding`/`Observation` evidence (distinguish
  observations from interpretations); shared `Knowledge` (libc, leaks, bases);
  begin generalized verification. Branch off current `main`.
- Then PRs 8–15: explicit primitive models; plan/execute separation; generalized
  objectives/verification; workspace persistence; analyze/plan/auto/assisted CLI;
  isolated execution backend; interactive frontend; release hardening + benchmark
  comparison. See `docs/ARCHITECTURE.md` and the roadmap document.

## Validation caveats

- Unit + `-race` suites pass. Because `internal/runner` is Linux-only, native
  execution, the `execution` integration tests, and end-to-end `solve` runs only
  exercise on Linux — PR 6's reordering has **not** been validated against the
  benchmark yet. Reproduce the baseline with `PwnProbe-benchmarks` before setting
  any numeric budget thresholds.
- Per-strategy attempt budgets are deferred pending reproduced baseline numbers.
- `internal/detect` still calls `internal/runner` directly (migrate to the
  executor facade in a later PR).
