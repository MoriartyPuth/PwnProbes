# Hybrid-framework roadmap — status

Tracks progress implementing the PwnProbes hybrid-framework roadmap (a shared
engine for auto / assisted / interactive binary-exploitation research while
retaining the existing solver). The full source plan — goals, interface
sketches, the 15-PR sequence, milestone gates, and acceptance criteria — is
[`docs/HYBRID_FRAMEWORK_ROADMAP.md`](HYBRID_FRAMEWORK_ROADMAP.md). This file
records what has landed against it and what is next.

Baseline before this work: `main` @ `78da9f5`.

## Done (22) — roadmap + follow-on complete, all merged into `main`

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
| 16 | `feat/resolve-plans` | Finish plan/execute for `ret2plt`: static recognition (pop-rdi gadget, exec PLT stub, in-binary command string) factored into a shared `Ret2pltResolution`/`resolveRet2pltFrom` that both `ret2pltStrategy` (execute) and `planRet2plt` (inspect) consume, so the plan carries the concrete gadget/string/stub addresses execution uses — verified to match on a real lab. Behaviour-preserving; the per-strategy import heuristic is replaced by real resolution. Other strategies follow incrementally. |
| 17 | `feat/scoring-planner` | Primitive composition: `composeChains` builds goal-directed, cross-strategy capability chains toward a shell/flag from the static resolution, established primitives, and shared `Knowledge` — e.g. a format-string/disclosed `LEAK` feeding `ret2libc`, a dependency single-strategy plans cannot express, reusing a known leak rather than rediscovering it. Each link is marked available or not; a chain is a hypothesis (reasoning only — execution and the honest oracle are unchanged). Deterministic. Additive `report.chains`, shown by `analyze`/`plan`/`solve`. |
| 18 | `feat/primitive-objectives` | Objectives grade from established primitives, not strategy names. A verified solve now establishes the primitive it demonstrated (control/write/call) from the winning strategy via a single `demonstratedBy` classification, referencing the flag finding at `exploitability_established`. `DemonstrateControl`/`DemonstrateWrite` read those primitives; `SpawnShell` reads a shell flag set from the same one place. The three per-objective strategy maps are removed. Objective statuses are unchanged on existing labs (verified on lab08); they now trace to primitives. |
| 19 | `feat/isolated-backend` | A supported isolated one-shot backend: `execution.Isolated` enforces memory/CPU/process limits via a POSIX `ulimit` wrapper that `exec`s the target in place (keeping the process group + bounds), declares those controls in `Enforces()`, and rejects network/filesystem isolation and the container level explicitly (no silent degradation). `SelectBackend` maps `none→Native`, `sandbox→Isolated`. Wired into `run --isolation sandbox [--max-memory/--max-cpu/--max-procs]`; a Linux test proves a CPU limit kills a busy loop. `solve` keeps its explicit rejection (its sessions are not isolated yet). Default execution unchanged. |
| 20 | `feat/libc-fingerprint` | Robust libc handling for `ret2libc`: `resolveBaseFromLeaks` fingerprints the base by matching each leak's fixed page offset against all exported libc symbols (via `libcSymbolOffsets`), picking the base the most distinct leaks agree on — so a puts/printf/… leak resolves, not only `system`. When no leak matches the local libc, it reports that the target libc likely differs and to pass `--libc`. Strictly more cases handled, no regression (lab07 is the only ret2libc lab and did not previously solve here). The held-out generalization benchmark (real ROP-Emporium binaries, reported separately) is recorded in `PwnProbe-benchmarks`. |
| 21 | `feat/compose-selection` | Wire the composer into execution: `applyComposition` promotes the terminal strategy of a *feasible, cheap* composed chain (a strong static signal — e.g. ret2plt when the binary has pop-rdi + a system/exec PLT stub + a command string) to the front of the non-expensive group, with recorded rationale (`report.selection`). PR 6's expensive-deferred ranking and the honest oracle are preserved; weaker (moderate) chains stay advisory. Measured: lab14 solves in ~4s vs ~70s (ret2plt tried first instead of after three failing strategies); no coverage regression. First increment of composition driving execution. |
| 22 | `feat/chain-execution` | Chain-as-unit execution: `chain_leak_ret2libc` runs a composed two-step flow in one session that no single recipe does — send a format-string trigger to leak a libc address, fingerprint and **establish** the libc base (recorded as `Knowledge.LibcBase`, an intermediate leak finding, and a libc-domain leak primitive), then **consume** that base in a ret2libc overflow. `libcBaseFor` reuses a base already in Knowledge instead of re-deriving it. Registered expensive, so PR 6's ranking defers it behind every cheaper technique — no regression, no slowdown on labs a direct recipe solves. Proven end-to-end with a scripted session (recovers the flag via the oracle). This is where composition changes *what* can be solved, not just order. |

Each PR is behavior-preserving except PR 6, which intentionally changes strategy
ordering (correctness preserved; the flag oracle and per-strategy gating are
unchanged).

## Next

The 15-PR hybrid-framework sequence is complete (0.5 → 1.0; see
[`docs/RELEASE.md`](RELEASE.md)). The post-1.0 plan — PRs 16–20, which turn the
instrumentation into a reasoning planner that composes primitives — is written up
in [`docs/HYBRID_FRAMEWORK_ROADMAP.md`](HYBRID_FRAMEWORK_ROADMAP.md) §30 and
summarized here. It is planned, not yet started.

| PR | Branch (planned) | Summary |
|----|------------------|---------|

All of PRs 16–20 have landed, plus PR 21 which begins wiring the composer into
execution (it now promotes a feasible cheap chain's strategy, with rationale).
Chain-as-unit execution has now landed (PR 22): `chain_leak_ret2libc` runs a
format-string-leak step that establishes the libc base and a ret2libc step that
consumes it, in one session — a class no single recipe solves. Further composed
chains (write-what-where sequences, heap leak → tcache, etc.) can be built on the
same establish-then-consume mechanism.
Breadth work (full heap, general ROP expansion, more architectures, richer UI)
stays optional and outside this sequence. See `docs/ARCHITECTURE.md`.


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
