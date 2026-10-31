# PwnProbe

PwnProbe is a Go CLI for inspecting Linux ELF binaries and collecting evidence from local CTF programs. It provides static inspection, bounded execution, format-string behavior probes, flag extraction, and an automatic solver for simple local challenges (format-string reads, format-string GOT overwrites, format-string writes to a saved return address that defeat full RELRO, stack-overflow variable/return overwrites, two-argument ret2win ROP, ret2syscall execve ROP, ret2plt calls of an imported function with an in-binary string argument, a ROP chain planner for multi-argument and chained calls, executable-stack shellcode, ret2libc, canary-bypass ret2win, PIE partial-overwrite without a leak, symbolic-execution solving of logic/argv/stdin puzzles, and a menu-driven heap use-after-free). It drives a local subprocess or a remote TCP service over one interactive session. Broader heap exploitation (tcache poisoning, libc-hook overwrites) is planned.

## Build

Requires Go 1.23 or later. The Go code has no third-party module dependencies.

```sh
go build -o bin/pwnprobe ./cmd/pwnprobe
```

On Windows, build the native inspector or cross-compile a Linux executable for WSL:

```powershell
go build -o bin/pwnprobe.exe ./cmd/pwnprobe
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
go build -o bin/pwnprobe-linux-amd64 ./cmd/pwnprobe
Remove-Item Env:GOOS
Remove-Item Env:GOARCH
```

The unit tests are platform-independent (no target execution) and run anywhere:

```sh
go test ./...
```

They cover flag extraction, payload serialization, input parsing (leak and
menu inference), and context cancellation. The end-to-end solve suite lives in
the separate [evaluation repository](#evaluation-suite).

## Usage

```sh
pwnprobe inspect --json ./target
pwnprobe run --timeout 1s --input ./input.txt --json ./target
pwnprobe detect --timeout 1s --json ./target
pwnprobe analyze ./target                       # static recon + candidate plans, no execution
pwnprobe plan ./target                          # candidate plans only, no execution
pwnprobe solve --timeout 2s --flag-pattern 'flag\{[^}]+\}' --json ./target
pwnprobe solve --plan-only ./target             # show plans, do not execute
pwnprobe auto ./target                          # alias for solve (auto + RecoverFlag)
pwnprobe assisted ./target                      # preview the plan; add --approve to execute
pwnprobe solve --save challenge.pwnprobe.json ./target   # persist the run as a workspace
pwnprobe workspace --verify ./target challenge.pwnprobe.json  # resume + identity check
pwnprobe interactive ./target                   # REPL over the engine
pwnprobe solve --remote host:1337 --flag-pattern 'flag\{[^}]+\}' ./local_copy
pwnprobe strategies
pwnprobe version
```

Use `./bin/pwnprobe` if the binary is not on PATH. Flags precede the target path. `run` sends EOF when no input file is specified. `run` exits nonzero if the target crashes, times out, or exits unsuccessfully; its JSON still records the outcome.

`run` and `solve` accept `--flag-pattern`, a regexp for the flag shape; an empty value uses a broad default (`name{...}`). `run` reports `recovered_flags`: pattern matches present in the output but not in the supplied input. A match that is a substring of the input is treated as echoed and never counted — a program reflecting caller-supplied bytes is not evidence that a secret was discovered.

`solve` runs `detect` first, then tries each applicable strategy and stops at the first payload that yields a non-echoed flag, reporting that exact payload as a reproducible winner. It exits nonzero when no flag is recovered; a crash is never reported as a solve. The target runs in its own directory so a flag file beside it is readable.

- **format_string** (when format-string behavior is confirmed): sends a bounded set of leak payloads (`%p` stack dump, positional `%N$s` reads). Stack-dump output is additionally reassembled from little-endian pointer leaks before matching, so a flag that never appears literally in stdout is still recovered.
- **stack_overwrite** (when the target is an executable PwnProbe can run): brute-forces a line-based overflow, appending each magic constant decoded from the binary's instructions and each function address (on fixed-address, non-PIE binaries) after increasing padding lengths. A flag that then appears in the output recovers both the correct offset and the required value — for example a guard variable that must equal a magic constant, or a redirect to a flag-printing function — without those being hardcoded. For ret2win targets that call into libc, a stack-aligning `ret` gadget is tried to clear the common `movaps` fault.
- **rop_ret2win_args** (when `pop rdi; ret` and `pop rsi; ret` gadgets are present on a fixed-address binary): solves a win function that requires two register arguments equal to specific constants. It first locates the offset and function with sentinel arguments the target echoes, then builds a ROP chain setting RDI and RSI from the binary's decoded constants and calling the function.
- **shellcode** (executable-stack binary that leaks its buffer address): writes shellcode at the buffer, pads to the return address, and overwrites it with the leaked buffer address. **ret2libc** (NX binary that leaks a libc address and has a `pop rdi; ret` gadget): resolves the libc base from the leak, finds `system()` and a `"/bin/sh"` string, and builds a `pop rdi; "/bin/sh"; system()` chain. Both read the leak and send the exploit within one live connection, so they work with ASLR enabled, then drive the spawned shell with `cat flag` across common flag paths.
- **fmt_got_overwrite** (non-PIE binary with a confirmed format string and a writable GOT, i.e. not full RELRO): finds the format argument offset, then overwrites a GOT entry (of a function called after the vulnerable `printf`, such as `puts`/`printf`/`exit`) with a win function's address using `%hhn` byte writes, so the next call through that entry runs win. Win-named functions are tried first.
- **fmt_write_ret** (non-PIE binary with a confirmed format string in a loop — defeats full RELRO): since the GOT may be read-only, it leaks the stack and writes the win address onto a saved return address (the stack stays writable), then exits the loop so the function returns into win. The leak and the write share one connection, so the leaked addresses stay valid; a single-shot format string cannot reach the stack this way (ASLR) and is reported as such.
- **ret2syscall** (non-PIE binary with `pop rax/rdi/rsi/rdx; ret` gadgets, a `syscall`, and a `"/bin/sh"` string — true of statically linked binaries): builds an `execve("/bin/sh", 0, 0)` ROP chain that calls the kernel directly, with no libc resolution, then drives the shell.
- **ret2plt** (non-PIE binary with a `pop rdi; ret` gadget, a PLT stub for `system`/`exec*`, and a command string already in the binary — no leak needed): loads RDI with the string's address and returns into the function's PLT stub, trying a stack-aligning `ret` for the movaps fault. It resolves the PLT stub from `.rela.plt` and the `FF 25` GOT-indirect jump, and prefers a `"…flag…"`/`"cat …"` string so `system("/bin/cat flag.txt")` prints the flag directly; a spawned shell is driven too. This solves the "call `system` with an in-binary string" class (for example ROP Emporium's `split`).
- **rop_planner** (fallback; non-PIE): synthesizes a ROP chain from the binary's own gadgets to call imported or in-binary functions with arguments harvested from the code (`movabs`/`mov` immediates, including those in a sibling shared object). It builds a *sequence* of multi-argument calls to a related function group (names sharing a prefix and a trailing ordinal, e.g. `callme_one/two/three`) — the multi-stage case the fixed recipes cannot express — by resolving a covering `pop`-sequence gadget (or composing single pops), placing the arguments, and chaining the calls. Runs after every recipe and verifies over a live session. This is the first increment of a general chain planner (`internal/rop`); it does not yet do write-what-where, `ret2csu`, or stack pivots.
- **heap_uaf** (menu-driven heap binary with a use-after-free, non-PIE): infers a conventional numbered menu (create / free / use / edit) by keyword, then frees an object and reclaims its chunk with a same-size allocation whose data overwrites the object's function pointer with a win function, which a later "use" action calls. No libc leak needed, and it does not touch tcache fd pointers so safe-linking does not apply. First increment of heap support; it does not yet do tcache poisoning, libc-hook overwrites (which need a leak), size-prompted allocators, or non-numeric menus.
- **angr_logic** (any binary, for logic/argv/stdin puzzles rather than memory corruption — e.g. a password or numeric-key check that gates `system`/`execve`): uses symbolic execution to find an `argv` and stdin that reach a shell/flag block, then replays that concrete input and keeps the flag only if it actually prints. Optional: it runs a Python interpreter that has [angr](https://angr.io) installed — `PWNPROBE_PYTHON=/path/to/venv/bin/python`, else `python3`; if angr is absent the strategy is skipped. Local only (the replay controls `argv`).
- **partial_overwrite** (PIE binary, no leak, read-style overflow): overwrites only the low 1–2 bytes of a saved return address to point at a win function. The low 12 bits are the fixed page offset (known from the binary); a two-byte overwrite reaches a 64 KiB window but leaves one ASLR nibble, so it retries across fresh runs (~1 in 16–32) until the base aligns. It needs a read that does not append a terminator, so the untouched high bytes survive. Win-named functions and common offsets are tried first.
- **canary_ret2win** (non-PIE binary with a stack canary and a format-string leak): finds the canary's position in the leak — a 64-bit value whose low byte is zero and whose top 16 bits are not, which separates it from a 48-bit pointer — then for each padding length and win function opens a connection, leaks that position live, and sends `padding + canary + saved-rbp + ret2win` so the stack check passes. Win-named functions are tried first. A canary with no leak cannot be bypassed this way.

## Remote and interactive sessions

`internal/session` provides one interactive transport for a local subprocess and a remote TCP service: send, `RecvUntil(delim)`, and a prompt-agnostic `RecvUntilIdle` that collects output up to a blocking read. The leaked-address strategies run over it, reading a leak and replying in the same connection — the capability one-shot execution cannot offer, and what lets them handle ASLR and remote targets.

`pwnprobe solve --remote host:port ./local_copy` analyzes the local binary copy (protections, gadgets, libc) and exploits the remote service over TCP. Remote mode runs the session strategies: the leaked-address ones (shellcode, ret2libc) first, then ret2syscall, canary-bypass ret2win, and an overflow-to-shell brute force for a guard variable that gates `system("/bin/sh")`. It assumes the local copy matches the remote binary. For ret2libc against a remote whose libc differs from this machine's, pass `--libc /path/to/target/libc.so.6` so offsets are resolved from the correct libc. The format-string strategies (GOT overwrite, write-to-return-address) and the one-shot overflow/ROP strategies run locally only for now. Session reads are bounded by an output cap and the run's deadline.

Inspection works on Windows and Linux. Execution and detection require Linux; use the Linux build inside WSL on Windows. Probes support x86/x64 executables where the OS provides the necessary loader and libraries.

## Engine model: analyze, plan, verify, persist

The solver, the CLI commands, and the interactive shell all drive one engine, so
analysis, planning, execution, verification, and persistence behave identically
through each.

- **Analyze and plan without executing.** `analyze` reports the binary's identity
  and capabilities and the candidate plans; `plan` (and `solve --plan-only`)
  reports just the plans. A plan carries ordered steps, a cost tier, a risk
  level, its static requirements (each shown met or unmet), the primitives it
  would produce, and whether it is feasible — produced from static analysis only.
  Pure planning never runs the target, so an infeasible strategy is explained
  rather than silently spending attempts. The deterministic strategies expose
  plans; session/symbolic/heap strategies remain execution-only (shown as
  `exec-only` by `strategies`).
- **Evidence, primitives, and knowledge.** A run records structured findings that
  separate what was observed from what it means — a crash is an `observed`
  observation, never an "overflow confirmed" — and the capabilities a
  vulnerability grants as explicit primitives (leak/write/control/call, with
  domain, width, repeatability, and references to the evidence that established
  them). Shared knowledge (an identified libc with provenance, disclosed
  stack/heap leaks) is recorded once and reused rather than rediscovered.
- **Generalized verification.** Besides the authoritative `recover_flag`
  objective (which is exactly `Solved`), each run is graded against a standard
  set — `establish_leak`, `demonstrate_control`, `demonstrate_write`,
  `spawn_shell` — on a ladder (`observed` → `confirmed` → `primitive_established`
  → `exploitability_established` → `objective_met`). A status is only as strong
  as its evidence, so partial progress (a leak, a demonstrated write) is reported
  even when no flag is recovered. See [`docs/RELEASE.md`](docs/RELEASE.md) for the
  full verification contract.
- **Assisted and interactive.** `assisted` previews the objective, execution
  policy, and candidate plans and does **not** run the target without `--approve`;
  approving executes through the same engine. `interactive` is a REPL
  (`info`, `analyze`, `plans`, `plan <id>`, `solve`, `findings`, `primitives`,
  `objectives`, `knowledge libc PATH`, `save`, `open`, …); injecting knowledge
  invalidates the current plans instead of reusing stale ones.
- **Workspaces.** `solve --save FILE` persists a run (target identity,
  capabilities, findings, primitives, knowledge, plans, attempts, objectives) as
  versioned JSON; `workspace FILE` summarizes it and `--verify ./binary` checks
  that the saved analysis still applies (a changed binary, architecture, or bit
  width is flagged, since saved addresses and plans do not transfer). `--redact`
  strips the remote endpoint, libc path, and absolute paths for an exported copy.
- **Execution policy.** The report names the backend that ran the target and the
  policy it enforces. Native execution is honest about its limits (see *Execution
  limits*): `solve --isolation sandbox|container` is **rejected explicitly**
  because the native backend cannot enforce it, rather than running with weaker
  isolation than requested.

## What it reports

- ELF architecture, entry point, imports, functions, libraries, and SHA-256 fingerprint.
- Evidence for NX, PIE, RELRO, RWX segments, symbol stripping, and stack-check symbols.
- Input-dependent format expansion confirmed using unique markers and a literal baseline.
- Process exit status, crash signal, deadline outcome, input/output transcripts, and truncated-output indicators.
- Flags disclosed in output that were not present in the supplied input, with echoed input excluded.
- For a format-string or stack-overflow target, an automatic solve attempt with the recovered flag and the reproducible payload that produced it.

Missing canary evidence is reported as unknown. Stack-check symbol presence does not establish protection of every function. A crash is an observation, not proof of an overflow or control of execution. A successful process exit does not establish exploitation success.

## Execution limits

The runner uses disposable working directories, a sanitized environment, process-group cleanup, a per-run deadline, a 1 MiB input limit, and a 1 MiB capture limit per output stream. Maximum per-run timeout is one minute.

The native backend is not a security sandbox. It does not restrict filesystem/network access, memory, CPU, or process count, and it declares as much: a policy requesting any of those controls, or `--isolation sandbox|container`, is rejected with an explicit unsupported-policy error rather than run with weaker isolation than asked for. Use trusted lab programs or run the entire tool in a restricted VM/container; a sandboxed backend is planned (roadmap §30, PR 19). Descendants that escape their process group are outside its cleanup guarantees. Static ELF size guards are not a security boundary for hostile parser inputs. Target output and imported workspace data are treated as untrusted data, and workspace artifact references cannot escape the workspace directory.

The one-shot `detect`/`run` probes handle a single stdin interaction ending in EOF; interactive menus and remote targets are driven by the session layer and the solver strategies instead. Files can change between inspection and execution; a saved workspace records the binary's hash so a later resume detects a changed target.

## Benchmark engine

The production benchmark engine accepts a caller-provided JSON manifest and requires Linux and GCC:

```sh
pwnprobe benchmark --manifest /path/to/manifest.json --json
```

Each manifest entry contains `name`, `source` (relative to the manifest), `flags`, expected `protections` statuses, and the boolean expectations `format_string`, `crash`, and `timeout`. Optional comparison with the original detector requires `original_baseline: true`, `--original /path/to/pwnpasi.py`, and a caller-provided `--baseline-script /path/to/adapter.py`.

Test code, fixtures, adapters, reports, and compiled binaries are excluded from this repository. The initial local validation passed six controlled fixture cases and the runner/metadata/CLI checks. An easy local format-string challenge was detected and a manually supplied flag-read input succeeded ten times; the patched control did not disclose the flag. These results are not a general exploit-success benchmark.

## Evaluation suite

The end-to-end solve suite — challenge sources, build recipes, a manifest, expected outcomes, and comparison results — lives in a separate repository so the tool can be cloned on its own: [**MoriartyPuth/PwnProbe-benchmarks**](https://github.com/MoriartyPuth/PwnProbe-benchmarks). It builds each lab, runs `pwnprobe solve`, and checks that the recovered flag matches, with results recorded per PwnProbe commit under `results/<commit>.{json,md}`, each tagged with the OS, glibc, and gcc of the run. The historical baseline solved **18/18 labs — covering every solve strategy — against commit `36acdbc`** on Ubuntu 24.04 / glibc 2.39; see [`results/36acdbc.md`](https://github.com/MoriartyPuth/PwnProbe-benchmarks/blob/main/results/36acdbc.md). The hybrid-framework work is behaviour-preserving, so coverage is unchanged; recent runs on a modern toolchain (Fedora 44 / glibc 2.43 / gcc 16) record **16/18**, the two misses being environment-only — `lab07_ret2libc` under the newer glibc and `lab11_ret2syscall` needing a static libc — not solver regressions. PwnProbe is also checked against the real third-party ROP Emporium binaries (`ret2win`, `split`, `callme` — all solved) in [`results/real-world-ropemporium.md`](https://github.com/MoriartyPuth/PwnProbe-benchmarks/blob/main/results/real-world-ropemporium.md). That repository also carries a `detect-manifest.json` for the detection `benchmark` command above. Small unit tests (parsing, payload serialization, cancellation, flag extraction) stay alongside the code here; the labs do not.

## Roadmap

Shipped through 1.0: the solver strategies listed above, and the hybrid-framework
engine built across a 15-PR sequence — a shared strategy registry with
deterministic ranking; a central `TargetContext` with first-class evidence,
explicit primitives, and shared knowledge; generalized objectives and a
verification ladder; inspectable plans separated from execution; workspace
persistence with identity checks; an execution-policy model; and the
`analyze`/`plan`/`auto`/`assisted`/`interactive` commands over one engine. The
compatibility policy, verification contract, security boundaries, and extension
guide are in [`docs/RELEASE.md`](docs/RELEASE.md); the full design is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and the per-PR history in
[`docs/ROADMAP_STATUS.md`](docs/ROADMAP_STATUS.md).

Planned next (post-1.0, roadmap §30, PRs 16–20): resolve plans from real static
analysis and finish the plan/execute split; a scoring planner that **composes
primitives** across strategies toward an objective; objectives graded from those
primitives; a supported isolated (sandboxed) execution backend; and robust libc
fingerprinting plus a held-out generalization benchmark. Breadth work — broader
heap exploitation (tcache poisoning, libc-hook overwrites), general ROP expansion
(`write4`/`ret2csu`/stack pivot), more architectures, and a richer TUI — remains
optional follow-on.

The project is an independent Go rebuild inspired by [PwnPasi](https://github.com/heimao-box/pwnpasi). Licensed under MIT.
