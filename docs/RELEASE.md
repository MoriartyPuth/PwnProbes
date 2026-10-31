# PwnProbes 1.0 — compatibility, verification contract, security boundaries, and extension guide

This document is the 1.0 release gate for the hybrid-framework work (roadmap
PRs 1–15). It states what is stable, how results are to be read, where the
security boundaries are, how to extend the framework, and where the measured
benchmark results live. For the design and the per-PR history see
[`ARCHITECTURE.md`](ARCHITECTURE.md) and [`ROADMAP_STATUS.md`](ROADMAP_STATUS.md).

## 1. Compatibility policy

The refactor was built to be behaviour-preserving. Concretely:

- **Commands.** `inspect`, `run`, `detect`, `solve`, `strategies`, and
  `benchmark` keep their behaviour and output. New commands — `analyze`, `plan`,
  `auto`, `assisted`, `interactive`, `workspace` — are additive. `auto` is an
  exact alias of `solve` (auto + the RecoverFlag objective).
- **The flag oracle is unchanged and authoritative.** A flag counts only when it
  is disclosed by the program and is absent from the input that produced it; a
  crash is never a solve. `Report.Solved` remains the single source of truth.
- **Report fields are additive.** PRs 7–13 added `context`, `verification`,
  `objectives`, `plans`, and `execution` to the solve report. Existing fields
  (`solved`, `flags`, `winning_attempt`, `attempts`, `timing`, `plan`,
  `rejected_strategies`, `detection`, `binary`, `limitations`) are unchanged, so
  an existing consumer keeps working.
- **Schemas are versioned.** The workspace file carries a schema version
  (`WorkspaceVersion`, currently `1.0`); a file whose major version differs is
  rejected rather than half-read.

## 2. Objective verification contract

Every solve is graded against a standard objective set, each mapped onto a
verification ladder. The contract is honesty: a status is only as strong as the
evidence for it.

Ladder (strongest last): `observed` → `confirmed` → `primitive_established` →
`exploitability_established` → `objective_met`; plus the off-ladder terminals
`inconclusive` and `unsupported`.

- `recover_flag` — authoritative; `objective_met` iff `Solved` (a non-echoed flag
  matched the pattern). Mirrored into `report.verification` for compatibility.
- `establish_leak` — `objective_met` when a leak primitive is established; a
  confirmed format string is `confirmed` (read behaviour shown, no address yet).
- `demonstrate_control` / `demonstrate_write` / `spawn_shell` — `objective_met`
  only when the run solved via a technique whose success demonstrates that
  capability (a conservative per-strategy classification). A bare crash reaches
  only `observed`; nothing is reported as met without a solve.

Honesty rules enforced across the evidence layer: a crash is only ever an
`observed` observation (never "overflow confirmed"); a `%p` read does not imply a
write; a successful control-flow solve does not retroactively fabricate a
primitive beyond what it demonstrates. Every established primitive references the
finding(s) that evidence it.

## 3. Security boundaries

PwnProbes runs untrusted target binaries. The boundaries are explicit:

- **Three execution contexts.** *Native local* execution runs with the host
  user's privileges; working-directory separation is a convenience, **not**
  security isolation. *Isolated local* execution would enforce a declared policy
  through a sandbox/container backend (future work). *Remote interaction*
  connects to an explicitly selected endpoint; local policy does not constrain
  the remote service.
- **No silent degradation.** The native backend declares exactly what it enforces
  (wall-clock timeout, output/input bounds, process-tree termination, scratch
  `HOME`/`TMPDIR`). A policy requesting a control it cannot provide — a memory,
  CPU, process, network, or filesystem limit, or an `--isolation` level — is
  rejected with an explicit `UnsupportedPolicyError`, never run with weaker
  isolation than asked for. The backend and effective policy appear in the report
  (`environment.backend`, `execution`).
- **Untrusted data.** Target output and imported workspace data are data, never
  instructions. Workspace schema versions, and artifact file names, are
  validated; artifact references cannot escape the workspace directory
  (`SafeArtifactPath`). A workspace can be exported `--redact`ed, stripping the
  remote endpoint, libc path, and absolute paths. Binary hashes and environment
  snapshots support reproducibility; they do not prove a target is safe.
- **Intended use.** PwnProbes is authorized security-research / CTF tooling. Run
  untrusted targets only where you accept native execution's lack of isolation,
  or add a sandboxed backend first.

## 4. Extension guide

The engine is composed of small seams; add capability without touching unrelated
code.

- **A new strategy.** Implement the recipe as a `*solver` method
  `func(context.Context) (bool, error)` and register it in `buildRegistry` with
  its modes, cost tier, and (optionally) a `planFn`. Use `newPlanned` when the
  strategy can describe an inspectable plan; `newLegacy` leaves it execution-only
  (explicit, `canPlan()==false`). Recognition/payload/oracle stay inside the
  strategy; use the shared `Executor`/`Session` so the backend stays swappable.
- **A new plan.** A `planFn(*TargetContext) Plan` returns steps, static
  requirements (each met/unmet), produced primitive kinds, and feasibility — read
  only from static analysis, never by executing the target.
- **A new objective.** Implement `Objective` (`ID`, `Verify(Outcome) Verification`)
  and add it to `StandardObjectives`. Grade from the `Outcome` projection only,
  and respect the ladder — do not report `objective_met` without demonstrating
  evidence.
- **A new execution backend.** Implement `execution.Executor` (and the
  `PolicyBackend` methods `BackendName`/`Enforces`/`ValidatePolicy`) so it
  declares what it enforces and rejects what it cannot. Keep `Native` as the
  default for trusted labs.

## 5. Measured benchmark results

Coverage and timing are measured, not promised. The authoritative, reproducible
results live in the separate
[`PwnProbe-benchmarks`](https://github.com/MoriartyPuth/PwnProbe-benchmarks)
repository under `results/<commit>.{json,md}`, each tied to a PwnProbe commit and
recording the OS, glibc, and gcc of the run.

- The historical baseline is `36acdbc` (18/18 synthetic labs on Ubuntu 24.04 /
  glibc 2.39 / gcc 13.3). Those figures are **comparison inputs, not performance
  targets**; reproduce them on the target host before setting any threshold.
- The hybrid-framework work (PRs 7–14) is behaviour-preserving: solve coverage is
  unchanged from the pre-refactor baseline on the same toolchain. The most recent
  recorded run documents the two environment-only gaps on current toolchains
  (`lab07_ret2libc` under a newer glibc; `lab11_ret2syscall` needing a static
  libc) — neither is a solver regression.
- Timings are host-specific. Report solve rate alongside failures and timeouts so
  successful-run timing never hides expensive failures.
