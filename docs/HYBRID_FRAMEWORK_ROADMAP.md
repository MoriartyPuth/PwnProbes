# PwnProbes Hybrid Framework Roadmap

**Compatibility-first evolution from PwnProbe 0.5.0 to 1.0**  
**Document date:** October 18, 2026  
**Status:** Proposed architecture and implementation roadmap

> Build a shared engine for automatic, assisted, and interactive binary exploitation research while retaining the existing solver investment.

## Document provenance and scope

This document consolidates the comprehensive plan in the referenced “Project Analysis Help” conversation. The retrieved assistant message is limited to 20,000 characters and ends during section 22. Sections 1–21 below preserve the substantive content and examples available from that message, with light editorial cleanup. Section 22 and the implementation roadmap that follows are explicitly **editorial completions** covering the requested migration, security, benchmark, release, PR, and acceptance details; they are not a verbatim recovery of the missing source.

Repository observations and timings are historical claims from the referenced conversation, not findings independently revalidated for this document. The original plan cited main-branch commit `78da9f5`; benchmark measurements cited `36acdbc`. No repository changes were made.

**Project references**

- [PwnProbes](https://github.com/MoriartyPuth/PwnProbes)
- [Architecture document](https://github.com/MoriartyPuth/PwnProbes/blob/main/docs/ARCHITECTURE.md)
- [Solver implementation](https://github.com/MoriartyPuth/PwnProbes/tree/main/internal/solve)
- [Benchmark repository](https://github.com/MoriartyPuth/PwnProbe-benchmarks)

## Navigation

- **Goals and baseline:** Sections 1–4
- **Core models and interfaces:** Sections 5–11
- **Session lifecycle, execution, and ROP:** Sections 12–14
- **Strategy ranking and planning:** Sections 15–16
- **Persistence, provenance, and verification:** Sections 17–20
- **CLI and interactive operation:** Sections 21–22
- **Package migration and security:** Sections 23–24
- **Benchmark enhancements:** Section 25
- **Version milestones:** Section 26
- **Pull request sequence:** Section 27
- **Acceptance criteria and next steps:** Sections 28–29

## Reading the interface examples

Go snippets are architectural sketches, not a compilable API specification. Supporting types such as `Primitive`, `SupportResult`, `Step`, and `Verification` must be defined during implementation. Preserve behavior through adapters before committing to public interfaces. CLI examples describe proposed commands unless identified as existing commands.

---

# 1. End goal

I would define PwnProbes as:

> **A modular binary exploitation framework that can inspect targets, discover and characterize exploitation primitives, plan candidate attack chains, execute them in a controlled environment, allow human intervention at any stage, and produce reproducible evidence.**

The important difference is that **automatic flag recovery becomes one possible objective**, not the architecture itself.

Your framework should ultimately support three ways of working:

| Mode | Purpose |
|---|---|
| **Auto** | PwnProbes analyzes, plans, executes, validates, and selects strategies itself. |
| **Assisted** | PwnProbes analyzes and plans, but the researcher approves or modifies actions. |
| **Interactive** | Researcher directly invokes analysis, primitives, sessions, ROP planning, etc. |

All three should use **the same underlying engine**.

That is the core architectural decision.

---

# 2. Where PwnProbes is today

The current design is already significantly stronger than a simple CTF script.

You currently have roughly:

```text
cmd/pwnprobe
     │
     ├── inspect
     ├── run
     ├── detect
     ├── solve
     └── benchmark
          │
          ▼
internal/
    inspect/
    detect/
    runner/
    session/
    extract/
    rop/
    solve/
    benchmark/
```

Your major capabilities already include:

```text
Static ELF inspection
        │
        ├── NX
        ├── PIE
        ├── RELRO
        ├── canary indicators
        ├── symbols
        ├── imports
        ├── libraries
        └── SHA256

Dynamic probing
        │
        ├── crash observation
        └── format-string confirmation

Exploitation
        │
        ├── stack overwrite
        ├── ret2win
        ├── ret2win with arguments
        ├── format-string leaks
        ├── GOT overwrite
        ├── saved-RIP format write
        ├── shellcode
        ├── ret2libc
        ├── ret2syscall
        ├── canary bypass
        ├── PIE partial overwrite
        ├── ret2plt
        ├── multi-call ROP planner
        ├── heap UAF
        └── angr solving

Transport
        │
        ├── local subprocess
        └── remote TCP
```

And your benchmark repository currently exercises **18 controlled labs** plus real ROP Emporium binaries.

The next architectural priority is **how those techniques are represented and orchestrated**.

---

# 3. The primary architectural limitation

The biggest issue is visible directly in [`internal/solve/solve.go`](https://github.com/MoriartyPuth/PwnProbes/blob/main/internal/solve/solve.go).

Local execution currently effectively does:

```go
localStrategies := []func(context.Context) (bool, error){
    s.fmtGotOverwriteStrategy,
    s.fmtWriteRetStrategy,
    s.heapUAFStrategy,
    s.stackOverwriteStrategy,
    s.ropRet2winArgsStrategy,
    s.ropExecveStrategy,
    s.ret2pltStrategy,
    s.shellcodeStrategy,
    s.ret2libcStrategy,
    s.canaryStrategy,
    s.angrStrategy,
    s.partialOverwriteStrategy,
    s.ropPlannerStrategy,
}
```

And remote mode has another manually maintained sequence.

That creates four problems.

### Strategy ordering is intelligence

Right now choosing a strategy is mostly equivalent to choosing its position in this slice.

That doesn't scale.

### Strategies contain several responsibilities

Individual solver functions often perform some combination of:

```text
recognition
probing
planning
payload creation
execution
interaction
verification
report generation
```

These need to become separable.

### Human intervention is difficult

There is no clean way for someone to say:

> "Show me what you discovered, but don't execute anything."

or:

> "Use this leaked libc address with the ROP planner."

### Strategies can't compose easily

Your architecture document already recognizes this.

The next level is:

```text
LEAK + WRITE + CONTROL + knowledge
                  ↓
                planner
                  ↓
                goal
```

Instead of:

```text
recognize exact challenge shape
          ↓
hard-coded exploitation recipe
```

---

# 4. The architecture I would move toward

I would make this the long-term structure:

```text
                       PwnProbes
                           │
                 ┌─────────┴─────────┐
                 │                   │
             Frontends             API
                 │
       ┌─────────┼────────┐
       │         │        │
     Auto     Assisted  Interactive
       │         │        │
       └─────────┼────────┘
                 ▼
             Workspace
                 │
        ┌────────┴────────┐
        │                 │
      Target           Evidence
        │                 │
        ▼                 ▼
      Recon ───────► Primitive Discovery
                         │
                         ▼
                      Planner
                         │
                    Candidate Plans
                         │
                         ▼
                    Strategy Engine
                         │
                         ▼
                 Execution Backend
                         │
             ┌───────────┴──────────┐
             │                      │
           Local                  Remote
             │
          Sandbox
             │
             ▼
                  Verification Engine
                         │
                         ▼
                      Report
```

The key concept is the **workspace**.

Everything goes into it.

---

# 5. Introduce a TargetContext

Right now information is distributed across `inspect.Report`, `detect.Report`, solver fields, libc paths, remote settings, etc.

Create a central model.

Something like:

```go
type TargetContext struct {
    Target      Target
    Binary      inspect.Report
    Findings    []Finding
    Primitives  []Primitive
    Knowledge   Knowledge
    Capabilities Capabilities
}
```

Where:

```go
type Target struct {
    Path        string
    SHA256      string
    Remote      *RemoteTarget
    Architecture Architecture
}
```

And:

```go
type Knowledge struct {
    Libc       *LibraryInfo
    PIEBase    *uint64
    LibcBase   *uint64
    StackLeaks []uint64
    HeapLeaks  []uint64
}
```

This becomes the **shared state** for every module.

Do not let every exploitation strategy rediscover the same information.

---

# 6. Make evidence first-class

Your existing detector already starts down this path:

```go
type Finding struct {
    Kind     string
    Status   string
    Evidence string
}
```

That is good, but too limited for the future planner.

I'd expand it.

For example:

```go
type Finding struct {
    ID         string
    Kind       FindingKind
    Confidence float64
    Source     string

    Evidence   []Observation
    Constraints []Constraint
}
```

Then observations might contain:

```go
type Observation struct {
    Type      string
    Value     any
    Timestamp time.Time
    AttemptID string
}
```

For example:

```text
Finding
    kind: FormatString
    confidence: 1.0

Evidence
    input: "PP...%p|%p..."
    output: "PP...0x7ffd...|0x..."
    reproducible: true
```

or:

```text
Finding
    kind: Crash
    confidence: 1.0

Evidence
    signal: SIGSEGV
    payload_length: 1024

Interpretation
    control: unknown
```

That distinction is important.

A crash should never silently become:

```text
buffer overflow confirmed
```

Your current detector correctly avoids that mistake. Preserve it.

---

# 7. Introduce primitives

This is the biggest conceptual upgrade.

A vulnerability isn't the important thing to a planner.

The important thing is:

> **What capability has the vulnerability given me?**

Represent those capabilities directly.

For example:

```go
type PrimitiveKind string

const (
    PrimitiveLeak    PrimitiveKind = "leak"
    PrimitiveWrite   PrimitiveKind = "write"
    PrimitiveControl PrimitiveKind = "control"
    PrimitiveCall    PrimitiveKind = "call"
    PrimitiveAlloc   PrimitiveKind = "alloc"
    PrimitiveFree    PrimitiveKind = "free"
)
```

A leak might be:

```go
type LeakPrimitive struct {
    Source      AddressDomain
    Width       int
    Repeatable  bool
    Controlled  bool
}
```

A write primitive:

```go
type WritePrimitive struct {
    Destination AddressConstraint
    Width       int
    Repeatable  bool
}
```

A control primitive:

```go
type ControlPrimitive struct {
    Target      string
    Partial     bool
    Width       int
}
```

Now:

```text
format string
```

isn't itself the ultimate abstraction.

It can produce:

```text
LEAK(stack)
WRITE(arbitrary-ish)
```

Likewise:

```text
stack overflow
```

might become:

```text
CONTROL(saved RIP)
```

or:

```text
WRITE(stack relative)
```

This is how PwnProbes starts becoming a framework rather than a recipe runner.

---

# 8. Refactor strategies without rewriting them

This part matters a lot.

I would **not rewrite your existing solvers**.

Wrap them first.

Introduce:

```go
type Strategy interface {
    ID() string
    Description() string

    Supports(*TargetContext) SupportResult

    Plan(
        context.Context,
        *TargetContext,
    ) ([]Plan, error)

    Execute(
        context.Context,
        Executor,
        Plan,
    ) (Outcome, error)
}
```

`Supports()` answers:

```text
Is this worth trying?
```

It should not execute the target.

For example:

```text
ret2plt

requires:
    amd64
    non-PIE or known PIE base
    stack control
    callable PLT entry
    useful string
```

If those aren't present:

```text
ret2plt: unsupported
reason: no usable imported function
```

rather than silently spending attempts.

---

# 9. Introduce a StrategyRegistry

Instead of hard coding methods into `solve.go`:

```go
localStrategies := []func(...)
```

move toward:

```go
registry.Register(
    formatStringStrategy{},
    fmtGOTStrategy{},
    fmtWriteRetStrategy{},
    stackOverwriteStrategy{},
    ret2winStrategy{},
    syscallStrategy{},
    ret2pltStrategy{},
    ret2libcStrategy{},
    canaryStrategy{},
    partialOverwriteStrategy{},
    heapUAFStrategy{},
    symbolicStrategy{},
    ropPlannerStrategy{},
)
```

Then the planner queries the registry.

This gives you:

```text
plugin-style extensibility
strategy metadata
capability filtering
manual strategy selection
unit-testable planning
```

Eventually users could implement strategies outside `internal/solve`.

---

# 10. Separate planning from execution

This is probably the most important actual code refactor.

Currently the strategy often:

```text
generates payload
runs target
checks result
tries next payload
```

Instead:

```text
Strategy.Plan()
       ↓
    []Plan
```

A plan might look like:

```go
type Plan struct {
    ID       string
    Strategy string
    Steps    []Step

    Cost     CostEstimate
    Risk     RiskLevel

    Requires []Requirement
}
```

For example:

```text
Plan: ret2plt

1. establish saved-RIP offset
2. load argument register
3. call system@plt
4. send command string pointer
5. verify objective
```

The human can inspect that.

Auto mode can execute it.

Assisted mode can approve it.

Interactive mode can modify it.

Same plan object.

---

# 11. Make execution a service

Right now solver code calls either:

```go
runner.Run(...)
```

or:

```go
session.Spawn(...)
session.Dial(...)
```

Introduce:

```go
type Executor interface {
    Run(context.Context, ExecutionRequest) (ExecutionResult, error)
    Open(context.Context, SessionRequest) (Session, error)
}
```

Then strategies don't care whether execution is:

```text
local process
container
namespace sandbox
remote TCP
future SSH runner
test mock
```

This also makes testing much easier.

---

# 12. Fix `internal/session` early

There is a real concurrency issue in the current code.

The pump does:

```go
c.chunks <- cp
```

If that channel fills:

```text
reader goroutine
      │
      ▼
blocked forever on send
```

Cancellation doesn't interrupt the blocked send.

Change that delivery to observe cancellation:

```go
select {
case c.chunks <- cp:
case <-c.ctx.Done():
    return
}
```

I would also add explicit lifecycle management.

Eventually:

```go
type Conn struct {
    ...
    wg sync.WaitGroup
}
```

Then `Close()`:

```text
cancel
close pipes/socket
terminate owned process
wait for pump
wait for process watcher
return
```

Tests should cover:

```text
target produces infinite output
consumer stops reading
channel fills
Close called
all goroutines terminate
```

This should be one of the first patches.

---

# 13. Separate execution isolation from working-directory behavior

[`internal/runner/runner.go`](https://github.com/MoriartyPuth/PwnProbes/blob/main/internal/runner/runner.go) correctly says:

> It is NOT a security sandbox.

Right now a target can effectively inherit the user's OS privileges.

For trusted CTF binaries that's understandable.

For a **general-purpose binary framework**, you need another layer.

Eventually:

```text
ExecutionPolicy
    ├── CPU limit
    ├── memory limit
    ├── process limit
    ├── output limit
    ├── filesystem policy
    ├── network policy
    ├── environment policy
    └── timeout
```

And:

```go
type ExecutionPolicy struct {
    Timeout       time.Duration
    MaxMemory     uint64
    MaxProcesses  int
    Network       NetworkPolicy
    Filesystem    FilesystemPolicy
}
```

Backends could eventually be:

```text
NativeRunner
SandboxRunner
ContainerRunner
RemoteRunner
```

I'd keep the existing runner as:

```text
NativeRunner
```

for compatibility.

---

# 14. Keep the ROP package and expand it

`internal/rop` is one of the most valuable parts of the current architecture.

You already have:

```text
catalog.go
solver.go
assemble.go
consts.go
```

This is already moving away from hardcoded recipes.

I would keep this design and progressively turn it into a general ROP subsystem.

Future phases can add:

```text
write-what-where planning
stack pivot planning
ret2csu modeling
bad-byte constraints
gadget side-effect modeling
memory-write primitives
multi-stage ROP
architecture-specific calling conventions
```

But don't make those the immediate priority.

The framework architecture should come first.

---

# 15. Fix strategy ranking before adding more strategies

Your benchmark exposes a major problem.

Current results at commit `36acdbc` include:

```text
lab15_rop_chain       255.8 s
lab10_canary          148.8 s
lab11_ret2syscall     128.6 s
```

And your benchmark notes that `lab15` spends around **90 seconds in angr before reaching the ROP planner**.

This is precisely why you need planning metadata.

Each strategy should estimate something like:

```go
type CostEstimate struct {
    Time      time.Duration
    Attempts  int
    Expensive bool
}
```

Then rank:

```text
cheap deterministic
        ↓
cheap heuristic
        ↓
moderate targeted
        ↓
expensive brute force
        ↓
symbolic execution
```

But target evidence should override this.

For example:

```text
Binary clearly exposes multi-call ROP shape
        ↓
rop planner gets high score

No logic-heavy branching evidence
        ↓
angr gets low score
```

You could potentially reduce a 255-second solve dramatically just from ordering.

---

# 16. Add a planner scoring model

Start simple.

Don't build some giant AI planner.

For each strategy calculate:

```text
Applicability score
Evidence confidence
Expected runtime
Expected attempts
Prerequisite completeness
Previous failures
```

For example:

```go
Score =
    Applicability*5 +
    EvidenceConfidence*3 +
    PrerequisiteCoverage*3 -
    Cost*2 -
    PreviousFailures
```

The exact numbers aren't important initially.

The important part is making the choice explicit and testable.

Planner output could be:

```text
Candidate strategies

1. rop_planner        score 92
   reason:
     stack control observed
     non-PIE
     multi-arg function group detected
     useful constants available

2. ret2plt            score 47
   reason:
     system imported
     candidate string found

3. angr_logic         score 14
   reason:
     expensive
     no strong logic-puzzle indicators
```

This is extremely useful in assisted mode.

---

# 17. Add a Workspace model

Interactive operation needs persistence.

Create something like:

```go
type Workspace struct {
    Version string

    Target Target

    Binary inspect.Report

    Findings   []Finding
    Primitives []Primitive
    Knowledge  Knowledge

    Plans    []Plan
    Attempts []Attempt
    Outcomes []Outcome
}
```

Save it as something like:

```text
target.pwnprobe.json
```

Then:

```bash
pwnprobe workspace new ./binary
pwnprobe workspace save challenge.ppw
pwnprobe workspace open challenge.ppw
```

Or a simpler UX:

```bash
pwnprobe analyze ./binary --save challenge.json
pwnprobe resume challenge.json
```

---

# 18. Make attempt provenance explicit

Your current `Attempt` is already useful:

```go
Strategy
Payload
PayloadHex
Note
Result
Candidates
Recovered
```

Expand rather than replace it.

Eventually:

```go
type Attempt struct {
    ID         string
    PlanID     string
    StrategyID string

    Input      Artifact
    Transcript Artifact

    Environment EnvironmentSnapshot

    Result      ExecutionResult
    Evidence    []Observation

    StartedAt time.Time
    EndedAt   time.Time
}
```

This gives you reproducibility.

For research use, that is extremely valuable.

---

# 19. Replace `Solved bool` with generalized objectives

Keep `Solved` for compatibility.

But internally introduce:

```go
type Objective interface {
    ID() string
    Verify(Outcome) Verification
}
```

Possible objectives:

```text
RecoverFlag
ReachFunction
SpawnShell
ReadFile
DemonstrateControl
EstablishLeak
DemonstrateWrite
CustomPredicate
```

Then your old behavior becomes:

```text
Objective:
    recover text matching (?i)flag\{...\}
```

instead of the entire solver architecture depending on flags.

---

# 20. Generalize verification

I would use statuses similar to:

```text
Observed
Confirmed
PrimitiveEstablished
ExploitabilityEstablished
ObjectiveMet
Inconclusive
Unsupported
```

For example:

```text
SIGSEGV
→ Observed

instruction pointer contains controlled pattern
→ PrimitiveEstablished

controlled call target reached
→ ExploitabilityEstablished

flag recovered
→ ObjectiveMet
```

This gives meaningful results even when the complete exploit isn't automated.

---

# 21. CLI redesign

Do this incrementally.

Do not break:

```bash
pwnprobe inspect
pwnprobe run
pwnprobe detect
pwnprobe solve
pwnprobe benchmark
```

Those should continue working.

Then add:

```bash
pwnprobe analyze ./target

pwnprobe strategies ./target

pwnprobe plan ./target

pwnprobe auto ./target

pwnprobe assisted ./target

pwnprobe interactive ./target
```

Eventually:

```bash
pwnprobe strategy list

pwnprobe strategy inspect ret2plt

pwnprobe attempt <plan-id>

pwnprobe evidence list

pwnprobe primitive list

pwnprobe report
```

`solve` can eventually become shorthand for:

```text
auto + RecoverFlag objective
```

That maintains compatibility.

---

# 22. Interactive shell later, after the engine

*Editorial completion; the beginning and command examples were available in the source.*

An eventual shell could expose:

```text
PwnProbe> target info
PwnProbe> findings
PwnProbe> primitives
PwnProbe> strategies
PwnProbe> plan rop_planner
PwnProbe> inspect plan 4
PwnProbe> execute 4
PwnProbe> knowledge set libc ./libc.so.6
PwnProbe> retry
```

Build the engine and ordinary CLI commands first. The interactive shell should call the same analysis, planning, execution, workspace, and verification services. Avoid moving strategy logic into command handlers.

Assisted mode must show the selected objective, prerequisites, evidence, steps, expected cost, execution policy, and material uncertainty before execution. A researcher can supply knowledge, choose a strategy, revise a candidate, or approve execution. Changes to knowledge should invalidate dependent plans rather than silently reuse stale addresses.

Interactive mode should support partial progress: establishing a leak or demonstrating control is useful even when no flag is recovered.

---

# 23. Package migration and compatibility

*Editorial completion.*

## 23.1 Proposed package responsibilities

Introduce boundaries incrementally; exact package names remain an implementation decision.

```text
cmd/pwnprobe/           CLI parsing and presentation
internal/core/         Shared target, evidence, primitive, and plan types
internal/workspace/    Persistence, artifact references, schema migration
internal/recon/        Coordination of inspection and discovery
internal/strategy/     Strategy interface, metadata, registry, adapters
internal/planner/      Eligibility, ranking, prerequisites, budgets
internal/execution/    Executor interface and backend adapters
internal/verify/       Objectives, verification, outcome classification
internal/report/       Human-readable and structured reports

Existing packages retained initially:
internal/inspect/
internal/detect/
internal/runner/
internal/session/
internal/extract/
internal/rop/
internal/solve/
internal/benchmark/
```

Keep shared models independent of CLI presentation and concrete execution backends. Avoid an import cycle between core types and `inspect.Report`: initially reuse existing reports through adapters; later move neutral report types only where this materially improves dependency direction.

## 23.2 Migration steps

1. Capture existing command behavior and report formats.
2. Introduce neutral shared types without relocating exploit code.
3. Wrap existing strategy methods behind adapters.
4. Register strategies in one registry used by both local and remote workflows.
5. Introduce capability checks that explain backend differences.
6. Move orchestration to the engine while preserving `solve` as a compatibility facade.
7. Extract payload construction, probing, and verification one strategy at a time.
8. Stabilize interfaces before considering an externally importable API.

Registry extensibility does not require dynamic Go plugins or loading arbitrary code. Start with explicit in-process registration. Do not publish every internal type as a permanent API.

Maintain legacy `Solved`, payload, and report fields through compatibility mappings. New generalized verification must determine those mappings consistently. Version workspace schemas independently from the application version.

---

# 24. Security boundaries and execution policy

*Editorial completion, extending the original runner proposal.*

## 24.1 Separate three execution contexts

| Context | Boundary and expected behavior |
|---|---|
| Native local execution | Runs with the host user's privileges; working-directory separation provides no security isolation. |
| Isolated local execution | Enforces a declared policy through a supported sandbox or container backend. |
| Remote interaction | Connects to an explicitly selected endpoint; local isolation does not constrain the remote service. |

Keep native execution available for existing trusted labs. Make the selected backend and effective policy visible in plans, attempts, and reports. If a requested isolation control cannot be enforced, fail with a clear unsupported-policy result rather than silently degrading.

## 24.2 Controls to model and enforce

- Wall-clock deadlines and cancellation.
- CPU, memory, process-count, and output limits.
- Process-tree termination and child reaping.
- Filesystem access, writable scratch space, and artifact export.
- Environment-variable inheritance and secret exposure.
- Network access for locally executed targets.
- Input, transcript, and workspace size bounds.

A container is a backend choice, not proof that every security requirement has been met. Record the actual configuration and platform limitations.

## 24.3 Artifact and workspace boundaries

Treat target output and imported workspace data as untrusted data. Validate schema versions, sizes, identifiers, and artifact paths. Prevent artifact references from escaping the workspace directory. Avoid persisting unrelated environment secrets.

Binary hashes and environment snapshots support reproducibility. They do not prove a target is safe. Credentials and remote connection secrets should be supplied separately from portable workspace files.

---

# 25. Benchmark enhancements

*Editorial completion, extending the original performance findings.*

## 25.1 Preserve the historical baseline

The referenced review reported 18/18 synthetic labs solved at `36acdbc`, plus ROP Emporium `ret2win`, `split`, and `callme`. Preserve that suite as a regression baseline and retain its original environment metadata.

| Historical target | Reported runtime |
|---|---:|
| `lab15_rop_chain` | 255.8 s |
| `lab10_canary` | 148.8 s |
| `lab11_ret2syscall` | 128.6 s |

These figures are comparison inputs, not promised performance targets. Reproduce them under controlled conditions before setting regression thresholds.

## 25.2 Measure the orchestration

For every run, capture:

- Target and binary hash, framework commit, backend, configuration, objective, and total budget.
- Analysis, planning, execution, and verification durations.
- Eligible and rejected strategies, rejection reasons, scores, selected order, and score components.
- Attempts per strategy, consumed budget, outcome, and verification evidence.
- Cancellation, timeout, unsupported, and infrastructure-failure results separately.
- Workspace and transcript artifact references.

Report solve rate alongside median and tail latency, attempt count, and per-strategy contribution. Include timeouts and failures in aggregate reporting so successful-run timing does not hide expensive failures.

## 25.3 Add focused coverage

1. **Planner fixtures:** deterministic ranking given fixed evidence; expensive symbolic execution does not precede strongly supported deterministic plans without an explicit reason.
2. **Backend capability checks:** one registry, explicit local/remote support, and useful rejection reasons.
3. **Session lifecycle:** output floods, stalled consumers, cancellation, repeated close, process exit, and remote disconnect.
4. **Evidence quality:** a crash alone never establishes instruction-pointer control.
5. **Workspace round trips:** preserve binary identity, knowledge provenance, plans, attempts, and verification; reject unsupported schema versions clearly.
6. **Budget behavior:** enforce global and per-strategy deadlines and attempt limits.
7. **Negative cases:** unsupported architectures, missing prerequisites, inconclusive probes, and unmet objectives.
8. **Isolation controls:** verify each advertised control on supported platforms.

Use repeated runs for noisy timing comparisons. Keep controlled synthetic labs for diagnosis and real challenge binaries for generalization; avoid tailoring all ranking rules to lab names.

---

# 26. Milestone versions: 0.5.x through 1.0

*Editorial completion. Versions describe delivery gates, not calendar commitments.*

| Version | Theme | Deliverables | Release gate |
|---|---|---|---|
| **0.5.x** | Reliability and baseline | Session cancellation fix, explicit lifecycle ownership, output/deadline controls, benchmark metadata, compatibility snapshots | Existing labs retain expected results; stalled-consumer close terminates; no unexplained legacy CLI regressions |
| **0.6** | Shared strategy orchestration | Strategy interface, adapters, common registry, support metadata, backend capability filtering, deterministic ranking | Local and remote query one registry; selection and rejection are explainable; existing solvers remain usable |
| **0.7** | Evidence and primitives | TargetContext, structured findings and observations, explicit primitive constraints, shared knowledge, generalized verification | Strategies reuse established knowledge; crash/control/objective distinctions are verified |
| **0.8** | Inspectable planning and persistence | Serializable candidate plans, workspace schema, attempt provenance, save/resume, plan-only CLI, assisted execution | Planning performs no hidden target execution; workspace round trips preserve evidence and provenance |
| **0.9** | Hybrid workflows and policy | Auto/assisted/interactive frontends, objective selection, execution-policy enforcement, benchmark reporting, migration documentation | All frontends share the engine; supported isolation policies are enforced; capability gaps are explicit |
| **1.0** | Stable framework contract | Stabilized CLI and schemas, documented extension interface, reproducibility workflow, release-wide acceptance review | Published compatibility policy, objective verification contract, security boundary documentation, and measured benchmark results |

## Delivery guidance

- Extract pure planning incrementally. Until a legacy adapter supports it, mark that strategy as legacy execution-only rather than presenting a fabricated inspectable plan.
- Introduce execution policy types early; do not wait until 0.9 to fix lifecycle or resource-control defects. The 0.9 gate concerns integrated supported enforcement.
- General ROP expansion, a rich terminal UI, dynamic plugins, SSH execution, and additional architectures are follow-on work unless required by a milestone's validated use cases.
- Set numerical latency targets after reproducing the baseline. Success includes preserving solve coverage while reducing demonstrably wasted strategy work.

---

# 27. Proposed pull request sequence

*Editorial completion. Each PR should be reviewable independently and preserve existing behavior unless its description explicitly identifies a change.*

| PR | Scope | Validation / acceptance |
|---|---|---|
| **1** | Session pump cancellation and lifecycle ownership | Fill the channel, stop consuming, close the connection, and confirm bounded shutdown; run relevant race checks |
| **2** | Baseline and attempt timing instrumentation | Reproduce controlled lab outcomes and record commit, environment, budgets, and per-strategy timing |
| **3** | Executor facade over runner and session | Existing local and TCP workflows work through adapters; cancellation propagates |
| **4** | Strategy interface and legacy wrappers | Preserve legacy behavior and reports; expose strategy IDs and descriptions |
| **5** | Common strategy registry and support results | Remove duplicated orchestration lists; explain backend limitations and missing prerequisites |
| **6** | Deterministic planner ranking and budgets | Fixed inputs produce stable order; strongly supported ROP candidates precede costly speculative fallback |
| **7** | TargetContext, evidence, and knowledge | Preserve detector semantics; attach provenance and reuse known facts |
| **8** | Explicit primitive models | Encode domains, widths, repeatability, constraints, and evidence references without overstating capability |
| **9** | Plan/execute separation for initial strategies | Inspectable plans for selected deterministic strategies; legacy execution-only strategies remain explicit |
| **10** | Generalized objectives and verification | Keep RecoverFlag/`Solved` compatibility; distinguish observation, primitive, exploitability, and objective success |
| **11** | Workspace persistence and attempt artifacts | Round-trip tests, schema handling, identity checks, and bounded safe artifact paths |
| **12** | Analyze, strategies, plan, auto, assisted CLI | Plan-only mode does not execute targets; assisted changes and execution use the same engine |
| **13** | Supported isolated execution backend | Enforce documented policies and reject unavailable controls; include process-tree and resource-limit checks |
| **14** | Interactive frontend and reports | Resume a workspace, inject knowledge, inspect a plan, execute it, and inspect objective evidence |
| **15** | Release hardening and benchmark comparison | Publish compatibility results, performance comparisons, security boundaries, and extension guidance |

Dependency guidance: PRs 1–2 establish the baseline. The executor and registry work can precede richer models through adapters. Evidence precedes trustworthy primitive composition. Persistence follows stable enough serializable models. Frontends follow usable engine services.

Do not combine a broad code move, solver rewrite, workspace redesign, and CLI replacement into one PR.

---

# 28. Acceptance criteria

*Editorial completion.*

## 28.1 Compatibility

- Existing `inspect`, `run`, `detect`, `solve`, and `benchmark` workflows remain supported.
- Existing solver coverage is retained under the same declared environment and budgets.
- Legacy `Solved` maps to verified objective success, not merely a crash or plausible payload.
- Report changes are additive or explicitly versioned with migration guidance.

## 28.2 Architecture

- Auto, assisted, and interactive workflows invoke the same engine.
- Local and remote execution use one strategy registry and explicit capabilities.
- `Supports()` is side-effect free; pure planning does not execute targets.
- Required discovery actions are modeled as explicit execution steps or a separate authorized discovery phase.
- Strategy selection records scores, reasons, prerequisites, and budget decisions.
- Existing solvers are adapted before being decomposed; useful `internal/rop` work is retained.

## 28.3 Evidence and reproducibility

- Findings distinguish observations from interpretations.
- Every established primitive references evidence and describes its constraints.
- Knowledge records its source, target identity, and relevant assumptions.
- Attempts connect objective, plan, strategy, inputs, transcript, environment, and verification.
- Save/resume detects binary or environment changes that invalidate addresses and plans.
- Sensitive configuration can be omitted or redacted from exported artifacts.

## 28.4 Reliability and execution

- Closing a session terminates blocked delivery and unblocks owned I/O.
- Process and goroutine ownership is explicit; cleanup is bounded and tested.
- Global deadlines, per-strategy budgets, and output bounds are enforced.
- Unsupported isolation policies fail explicitly.
- Reports identify the backend and effective execution policy.

## 28.5 User workflows

- A researcher can inspect analysis and candidate plans before execution.
- A researcher can supply a known libc or leak with provenance.
- A researcher can select a strategy and understand why alternatives were rejected.
- Partial outcomes remain useful when the full objective is not met.
- Recovered flags, controlled calls, leaks, and writes are verified using objective-appropriate evidence.

## 28.6 Performance

- Controlled benchmark coverage does not regress without an explained, accepted change.
- The planner avoids the documented expensive-before-supported-ROP ordering when the evidence supports ROP.
- Published comparisons include failures, timeouts, attempt counts, and environment details.
- Numerical release thresholds are set from reproducible measurements rather than historical anecdotes.

---

# 29. Immediate next steps

*Editorial completion.*

1. **Freeze the baseline.** Record the code revision, benchmark revision, environment, current CLI/report contracts, solve coverage, and per-strategy timing.
2. **Fix session shutdown.** Make chunk delivery cancellation-aware, define channel ownership, close owned I/O, terminate owned processes, and wait for lifecycle workers. Verify the full-channel/stalled-reader case first.
3. **Add the smallest strategy wrapper.** Preserve existing methods while exposing identity, description, backend support, and legacy execution behavior.
4. **Create the common registry.** Replace duplicated strategy orchestration with capability-driven selection and explicit rejection reasons.
5. **Make ordering measurable.** Add budgets and deterministic ranking; compare the multi-call ROP lab against the historical costly ordering.
6. **Introduce shared evidence and knowledge.** Keep existing reports available while exposing structured facts to strategies.
7. **Extract one real plan.** Choose a well-understood deterministic strategy, separate planning and execution, and show the same plan through automatic and assisted workflows.
8. **Review the first milestone against its gates.** Deliver the reliability and compatibility improvements before expanding into a rich interactive shell or additional exploitation techniques.

The first concrete deliverable is a compatibility-preserving session reliability patch with a reproducible baseline. The architectural destination is one shared engine that turns observations into constrained primitives, explicit plans, controlled execution, and verifiable outcomes.


---

# 30. Follow-on pull request sequence (16–20): from instrumentation to composition

*Post-1.0 plan. PRs 1–15 built the shared engine, the evidence/primitive/plan/
objective models, persistence, policy, and the frontends — but the engine still
describes and grades runs more than it reasons over them. Each strategy's `Run`
still hardcodes recognition → payload → oracle, nothing composes primitives
across strategies, and the inspectable plans are declarative intent rather than
plans resolved from the binary. These five PRs turn the instrumentation into a
reasoning planner. The honest flag oracle and `Solved` stay authoritative
throughout; everything remains behaviour-preserving unless a PR says otherwise.*

| PR | Scope | Validation / acceptance |
|---|---|---|
| **16** | Resolve plans from real static analysis (finish plan/execute) | Factor each strategy's recognition phase into a `Resolve(*TargetContext)` that finds concrete gadgets/strings/GOT entries and records them as primitives; `Plan` and `Execute` call the same `Resolve`, so a plan carries the real addresses it will use. Existing solves unchanged; a plan's resolved artifacts match what execution uses. |
| **17** | Scoring planner that composes primitives (roadmap §16) | Strategies declare primitive **requirements** as well as `Produces`; a bounded backward-chaining/scoring search composes established primitives toward an objective (e.g. `SpawnShell` ← `CALL(system)` ← `CONTROL` + libc base ← `LEAK(libc)`), reusing shared `Knowledge` so a leak feeds a later chain without rediscovery. A composed chain is a hypothesis until the oracle verifies it. Deterministic given fixed evidence; expensive speculation never precedes a strongly-supported composed plan without a recorded reason. |
| **18** | Objectives grade from established primitives | Replace the per-strategy capability classification (PR 10) with grading read directly from the primitives PRs 16–17 establish, removing the strategy-name heuristic and its drift risk. Objective statuses unchanged on the existing labs. |
| **19** | Supported isolated execution backend | Implement an `Isolated` backend behind the `PolicyBackend` interface: an rlimit trampoline (memory/CPU/process) plus optional namespace isolation (network-none, read-only FS) via a supported sandbox tool. `--isolation sandbox` enforces rather than rejects where the platform supports it; unsupported controls still fail explicitly. Process-tree and resource-limit checks on supported platforms. |
| **20** | Robust libc handling + generalization benchmark | Make `ret2libc` identify the leaked symbol by fingerprinting the libc (try all exported offsets; libc-database style) instead of assuming `system`, emitting a finding when local libc ≠ target; add a cross-glibc lab matrix. Add a **held-out** generalization benchmark (real binaries no strategy was tuned to) reported separately from the known-to-implementation suite, with solve rate, median+tail latency, and failures, and thresholds set from measured numbers. |

Dependency guidance: PRs 16 and 17 are the keystone and are best done together —
16 gives the planner concrete primitives to compose, and 18 then falls out of
17 for free. PRs 19–20 harden and give the composition credibility; do them
after the planner exists, not before. Breadth items (full heap: tcache poisoning
on glibc 2.27–2.31; general ROP expansion: `write4`/`ret2csu`/stack pivot, §14;
additional architectures; a richer terminal UI) remain optional follow-on work
outside this sequence.
