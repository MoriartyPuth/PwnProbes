# Hybrid-framework roadmap — status

Tracks progress implementing the PwnProbes hybrid-framework roadmap (a shared
engine for auto / assisted / interactive binary-exploitation research while
retaining the existing solver). The full source plan — goals, interface
sketches, the 15-PR sequence, milestone gates, and acceptance criteria — is
[`docs/HYBRID_FRAMEWORK_ROADMAP.md`](HYBRID_FRAMEWORK_ROADMAP.md). This file
records what has landed against it and what is next.

Baseline before this work: `main` @ `78da9f5`.

## Done (15 of 15) — roadmap complete, all merged into `main`

| PR | Branch | Summary |
|----|--------|---------|
| 1 | `fix/session-pump-cancellation` | `internal/session` pump send is cancellation-aware; `Conn` owns a cancel func + `WaitGroup`; `Close()` is a bounded shutdown. |
| 2 | `feat/baseline-timing-instrumentation` | Solve report gains an `Environment` block (commit/go/os/arch/mode/budget) and per-strategy `Timing`; strategies are named and routed through one timing path. |
| 3 | `feat/executor-facade` | `internal/execution` adds `Executor`/`Session` interfaces + a `Native` adapter over runner+session; the solver runs through an injected executor. `Request`/`Result` alias the runner types. |
| 4 | `feat/strategy-interface` | `Strategy` interface (`ID`/`Description`/`Supports`/`Cost`/`Run`) + legacy wrappers; `Catalog()` and a `pwnprobe strategies` command. |
| 5 | `feat/strategy-registry` | One `registry` both modes query, replacing the two per-mode lists; `Supports`/`SupportResult` capability filtering with explained rejections (`rejected_strategies` in the report). |
| 6 | `feat/planner-ranking` | `CostEstimate` + `Cost()`; `registry.eligible` ranks deterministically — historical mode order kept, expensive strategies (angr, cross-run/session brute force) stably deferred, so `rop_planner` precedes `angr`. Global deadline enforced between strategies; report `plan`; cost tiers in `strategies`. |
| 7 | `feat/target-context-evidence-knowledge` | Central `TargetContext` (`Target` identity, `Capabilities`, `Findings`, `Knowledge`) shared across the solver. First-class evidence: `Finding`/`Observation` separate what was observed from what it means — a crash stays `observed`, never an overflow claim. Shared `Knowledge` (libc with provenance, stack/heap leaks) recorded once and reused (`ret2libc` consults the memoized libc). Generalized verification begun: `VerificationStatus` ladder + `Objective`/`RecoverFlag`; `Solved` kept authoritative. Additive report fields `context`/`verification`. |
| 8 | `feat/explicit-primitives` | Explicit primitive models (`Primitive`: `PrimitiveKind`, `AddressDomain`, `AddressConstraint`, width, repeatability, controlled, evidence refs). `TargetContext.Primitives` filled by `establishPrimitives`, derived once at end of run from established evidence only — a confirmed format string ⇒ controlled stack `LEAK`; runtime-disclosed pointers ⇒ uncontrolled `LEAK` per domain. No overstating: a crash establishes nothing, and a control-flow solve does not fabricate a `CONTROL` primitive. Every primitive references the finding(s) that evidence it. Additive `context.primitives`. |
| 9 | `feat/plan-execute-separation` | Inspectable `Plan` (steps, cost, risk, requirements, produced primitives, feasibility) produced without executing the target. Selected deterministic strategies (`stack_overwrite`, `rop_ret2win_args`, `rop_execve`, `ret2plt`, `rop_planner`, `partial_overwrite`) describe their plan via a `planFn`; session/symbolic/heap strategies stay execution-only (`canPlan()==false`, shown in `strategies`). `Run` is unchanged — no solver rewrite. `solve --plan-only` and `PlanOnly` emit plans with zero attempts and no detection probe (pure planning does not execute). Additive `report.plans`, `StrategyInfo.plannable`. |
| 10 | `feat/generalized-objectives` | Generalized verification: a run is graded against a standard objective set — `RecoverFlag`, `EstablishLeak`, `DemonstrateControl`, `DemonstrateWrite`, `SpawnShell` (+ `CustomPredicate`) — each mapping to the `VerificationStatus` ladder. Honest grading: a leak primitive ⇒ `EstablishLeak` met; a solve via a control/write/shell-class technique ⇒ the matching objective met; a crash reaches only `Observed`; nothing is promoted without a solve. `RecoverFlag`/`Solved` stay authoritative (`report.verification` mirrors `RecoverFlag`). Additive `report.objectives`. |
| 11 | `feat/workspace-persistence` | `Workspace` model (schema `1.0`): target identity, capabilities, findings, primitives, knowledge, plans, attempts, objectives. `WorkspaceFromReport` + `Save`/`LoadWorkspace` round-trip JSON with major-version schema handling. `VerifyAgainst`/`VerifyPath` detect a changed binary/arch/bits on resume (stale addresses/plans flagged). `Redacted` strips remote endpoint, libc path, absolute paths. `SafeArtifactPath`/`checkArtifactName` bound artifact names to their directory. CLI: `solve --save[/--redact]`, `workspace [--verify <bin>]`. Additive. |
| 12 | `feat/cli-analyze-plan-auto-assisted` | New commands over the same engine, compatibility preserved (`inspect`/`run`/`detect`/`solve`/`benchmark` unchanged): `analyze` (static recon + capabilities + candidate plans, no execution), `plan` (candidate plans, no execution), `auto` (alias for `solve` = auto + RecoverFlag), `assisted` (previews objective/execution-policy/plans and does **not** run the target without `--approve`; `--approve` executes via the same engine). All reuse `PlanOnly`/`Solve`. |
| 13 | `feat/execution-policy` | `ExecutionPolicy` + backend capability model (`internal/execution`): controls (timeout, output/input bounds, process-tree kill, scratch dirs, memory/cpu/process/network/filesystem). `Native` declares its honest enforced set (it is not a sandbox) and `ValidatePolicy` returns an explicit `UnsupportedPolicyError` for any isolation control it cannot provide — never silently degrading. Backend + effective policy surfaced in the report (`environment.backend`, `execution`). `solve --isolation sandbox|container` is rejected before running. Native stays the default; default policy validates cleanly (no behavior change). |
| 14 | `feat/interactive-frontend` | `internal/repl`: an interactive shell over the same engine services (no strategy logic in handlers). Commands: `info`, `analyze`, `plans`, `plan <id>`, `strategies`, `solve`, `findings`, `primitives`, `objectives`, `knowledge [libc PATH]`, `save`, `open`/`resume`, `help`, `quit`. Injecting knowledge invalidates the current plans (re-analyze on next use). Reuses `PlanOnly`/`Solve`/`Workspace`; supports partial progress (objective evidence shown without a flag). Driven by an `Engine` interface, so it is unit-tested with a fake (no ELF, no execution). CLI: `pwnprobe interactive <target>`. |
| 15 | `feat/release-hardening` | Release hardening + 1.0 gate: [`docs/RELEASE.md`](RELEASE.md) publishes the compatibility policy, the objective-verification contract, the security-boundary summary, and the extension guide, and points to the measured benchmark results in `PwnProbe-benchmarks/results/`. Version bumped to `1.0.0`. No engine behaviour change. |

Each PR is behavior-preserving except PR 6, which intentionally changes strategy
ordering (correctness preserved; the flag oracle and per-strategy gating are
unchanged).

## Next

The 15-PR hybrid-framework sequence is complete (0.5 → 1.0; see
[`docs/RELEASE.md`](RELEASE.md)). Follow-on work remains optional and is not part
of this sequence: a sandboxed/container execution backend, broader heap
exploitation, general ROP expansion (write-what-where, `ret2csu`, stack pivot),
additional architectures, and a richer terminal UI. See `docs/ARCHITECTURE.md`.


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
