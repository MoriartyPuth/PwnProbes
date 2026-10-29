# Hybrid-framework roadmap — status

Tracks progress implementing the PwnProbes hybrid-framework roadmap (a shared
engine for auto / assisted / interactive binary-exploitation research while
retaining the existing solver). The full source plan — goals, interface
sketches, the 15-PR sequence, milestone gates, and acceptance criteria — is
[`docs/HYBRID_FRAMEWORK_ROADMAP.md`](HYBRID_FRAMEWORK_ROADMAP.md). This file
records what has landed against it and what is next.

Baseline before this work: `main` @ `78da9f5`.

## Done (7 of 15), all merged into `main`

| PR | Branch | Summary |
|----|--------|---------|
| 1 | `fix/session-pump-cancellation` | `internal/session` pump send is cancellation-aware; `Conn` owns a cancel func + `WaitGroup`; `Close()` is a bounded shutdown. |
| 2 | `feat/baseline-timing-instrumentation` | Solve report gains an `Environment` block (commit/go/os/arch/mode/budget) and per-strategy `Timing`; strategies are named and routed through one timing path. |
| 3 | `feat/executor-facade` | `internal/execution` adds `Executor`/`Session` interfaces + a `Native` adapter over runner+session; the solver runs through an injected executor. `Request`/`Result` alias the runner types. |
| 4 | `feat/strategy-interface` | `Strategy` interface (`ID`/`Description`/`Supports`/`Cost`/`Run`) + legacy wrappers; `Catalog()` and a `pwnprobe strategies` command. |
| 5 | `feat/strategy-registry` | One `registry` both modes query, replacing the two per-mode lists; `Supports`/`SupportResult` capability filtering with explained rejections (`rejected_strategies` in the report). |
| 6 | `feat/planner-ranking` | `CostEstimate` + `Cost()`; `registry.eligible` ranks deterministically — historical mode order kept, expensive strategies (angr, cross-run/session brute force) stably deferred, so `rop_planner` precedes `angr`. Global deadline enforced between strategies; report `plan`; cost tiers in `strategies`. |
| 7 | `feat/target-context-evidence-knowledge` | Central `TargetContext` (`Target` identity, `Capabilities`, `Findings`, `Knowledge`) shared across the solver. First-class evidence: `Finding`/`Observation` separate what was observed from what it means — a crash stays `observed`, never an overflow claim. Shared `Knowledge` (libc with provenance, stack/heap leaks) recorded once and reused (`ret2libc` consults the memoized libc). Generalized verification begun: `VerificationStatus` ladder + `Objective`/`RecoverFlag`; `Solved` kept authoritative. Additive report fields `context`/`verification`. |

Each PR is behavior-preserving except PR 6, which intentionally changes strategy
ordering (correctness preserved; the flag oracle and per-strategy gating are
unchanged).

## Next

- Then PRs 8–15: explicit primitive models; plan/execute separation; generalized
  objectives/verification; workspace persistence; analyze/plan/auto/assisted CLI;
  isolated execution backend; interactive frontend; release hardening + benchmark
  comparison. See `docs/ARCHITECTURE.md` and the roadmap document.

## Validation caveats

- Unit + `-race` suites pass. Because `internal/runner` is Linux-only, native
  execution, the `execution` integration tests, and end-to-end `solve` runs only
  exercise on Linux.
- PR 6's reordering has now been run against `PwnProbe-benchmarks` on Linux
  (Fedora 44, glibc 2.43, gcc 16): every lab that builds and whose class is
  covered still recovers its flag, so the reordering did **not** regress
  coverage. Two environment-only gaps on this toolchain, not code regressions:
  `lab07_ret2libc` does not match the leaked libc address under glibc 2.43, and
  `lab11_ret2syscall` needs a static libc that is not installed. `lab12` now
  wins via `stack_overwrite` rather than `partial_overwrite` — the intended PR 6
  effect (cheap/targeted before deferred-expensive), flag still recovered.
- Benchmark timings are host-specific (several ROP labs run materially slower
  here than the recorded `36acdbc` baseline). Set any numeric budget thresholds
  from numbers reproduced on the target host, not from the historical results.
- Per-strategy attempt budgets are deferred pending reproduced baseline numbers.
- `internal/detect` still calls `internal/runner` directly (migrate to the
  executor facade in a later PR).
