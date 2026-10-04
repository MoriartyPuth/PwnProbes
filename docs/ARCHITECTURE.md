# PwnProbe architecture and roadmap

This document describes how PwnProbe is structured today, why that structure has
a ceiling, and how it would evolve to reach harder challenge classes (heap,
PIE-without-leak, logic/argv puzzles, and full-RELRO GOT).

## Today: recipe-based strategies

The solver is a list of **strategies**, each a self-contained recipe:

> recognize a shape → build a payload → brute one parameter → check the flag oracle

`internal/solve` holds one file per family:

- `solve.go` — the orchestrator and the shared `solver`/`Attempt`/`Report` types.
- `overwrite.go` — variable overwrite and ret2win (immediate decoding, gadget and
  function scans, stack-aligning `ret`).
- `rop.go` — two-argument ret2win ROP (`pop rdi`/`pop rsi`).
- `rop_syscall.go` — `execve("/bin/sh")` ROP from syscall gadgets.
- `leak.go` — shellcode-on-stack, ret2libc, and the session-based overflow.
- `canary.go` — canary leak via format string, then overflow preserving it; also
  `orderedWinFunctions` (win-named first, CRT stubs dropped), shared with others.
- `fmt_got.go` — format-string GOT overwrite with `%hhn`.

Support packages:

- `internal/inspect` — static ELF facts: arch, protections (NX/PIE/RELRO/canary),
  symbols, imports, libraries, SHA-256.
- `internal/extract` — the echo-aware flag extractor (a match counts only when it
  is absent from the input that produced it) and little-endian leak reassembly.
- `internal/session` — one interactive transport for a local subprocess and a
  remote TCP service: `Send`, `RecvUntil`, and the prompt-agnostic
  `RecvUntilIdle`. This is what lets a leak be read and used in one connection.
- `internal/runner` — the bounded one-shot execution used by `run`/`detect` and
  the fast overflow brute force.

The oracle is uniform: a strategy wins only when a non-echoed flag matching the
pattern appears in the transcript.

### Why this has a ceiling

Each recipe hardcodes the whole path from vulnerability to flag. That is fine for
"linear" challenges where one primitive plus a brute reaches the goal, but it
cannot compose primitives, reason about program logic, or model a stateful
allocator. The harder classes each need a missing capability, not another recipe.

## Target architecture: primitives and a planner

```
Recon            protections, symbols, gadgets, GOT, strings, libc identification
   │
Primitives       LEAK   (format-string read, uninitialised read)
   │             WRITE  (format-string %n, buffer overflow)
   │             CONTROL(saved return address, function pointer)
   │             each characterised: where, how many times, width, bad bytes
   │
Knowledge        libc offsets / one_gadget; glibc heap allocator model
   │
Planner          goal = spawn shell | read flag; search a chain over primitives
   │
Interaction      session: menus, leak-then-respond
   │
Oracle           echo-guarded flag extraction
```

Today the planner is a fixed list and primitives are implicit. The evolution is
to make primitives first-class (discover and describe them) and add a planner
that composes them toward a goal. Simple cases stay as direct recipes; hard cases
use the planner or an external engine.

## The four hard classes

### 1. Full-RELRO GOT — DONE (`fmt_write_ret`)

Full RELRO only makes the GOT read-only; the **stack and libc stay writable**, so
the write primitive is retargeted rather than the mitigation defeated.

- GOT entry overwrite (partial RELRO) — `fmt_got.go`.
- **Saved return address on the stack** (any RELRO) — `fmt_writeret.go`: for a
  looping format string, leak the stack and write a win address onto a saved
  return address, then exit the loop so the frame returns into win. The leak and
  the write share one connection so the leaked addresses stay valid; the canary
  is untouched. Implemented and validated against a full-RELRO looping lab.
- Still open: a single-shot full-RELRO target has no reachable fixed writable
  function pointer, so it needs a program-specific hook; and libc hooks
  (`__free_hook`/`__malloc_hook`, glibc < 2.34) need a libc leak plus a reachable
  `free`/`malloc` with a controllable argument.

### 2. PIE without a leak — DONE (`partial.go`)

No leak at all is unsolvable on 64-bit (≈28 bits of base entropy), so the
implemented technique is the **partial overwrite**: overwrite only the low 1–2
bytes of a saved return address. The page-aligned low 12 bits are fixed under
PIE, so a one-byte overwrite redirects within a 256-byte block for free, and a
two-byte overwrite reaches a 64 KiB window leaving one ASLR nibble. Since there
is no leak, `partial.go` retries across fresh runs (each connection re-randomises
the base) until the nibble aligns — roughly 1 in 16, nearer 1 in 32 once the
64 KiB-carry edge case is counted. It requires a read-style overflow that does
not append a terminator, so the untouched high bytes survive; the offset and win
function are brute-forced, win-named functions first. Validated against a PIE
read-overflow lab (solved in ~50 s). 32-bit PIE (~8 bits) would be bruteable more
cheaply; a cooperative leak still reduces this to the PIE-with-leak case.

### 3. Logic / argv / file-descriptor puzzles — DONE (`angr.go`)

These are program comprehension, not memory corruption, so the engine is
**symbolic execution** (angr). `angr.go` writes a self-contained harness to a
temp file and runs it under a Python that has angr (`PWNPROBE_PYTHON`, else
`python3`; skipped when absent). The harness builds a CFG, finds blocks that
reach a shell/flag (call sites of `system`/`execve`/… or a win function), makes
argv[1..3] and stdin symbolic (printable), explores to a target, and prints the
solving argv and stdin. PwnProbe then **replays** the concrete input through the
one-shot runner and keeps the flag only if it actually prints — same honest
oracle as every other strategy. Local only (the replay controls argv), bounded by
a subprocess timeout. Validated against an argv+stdin logic lab (~5 s).

Known limits: a read from a *symbolic* file descriptor (as in pwnable.kr `fd`) is
modelled loosely, so the solved input may not replay; and the replay needs a
binary this host can execute (a 32-bit target needs multilib). The strategy suits
password/key/argv checks, the common logic class.

### 4. Heap exploitation — STARTED (`heap.go`), long-term track

First increment implemented: a menu-driven **use-after-free that overwrites an
in-binary function pointer**. `heap.go` infers a conventional numbered menu by
keyword (create / free / use / edit), then runs create → free → reclaim-with-win
→ use, brute-forcing the function-pointer offset. It needs no libc leak (non-PIE
win) and does not touch tcache fd pointers, so safe-linking (glibc >= 2.32) is
moot. Validated against a UAF lab (~9 s). A related fix: the one-shot overflow
brute now abandons a target that only loops (interactive menu) after repeated
deadline timeouts, and heap runs before it.

The rest of the heap track remains the large part below:

### Full heap — research-grade, largest remaining project

Needs three capabilities PwnProbe lacks:

1. **Menu/protocol model** — map interactive menu options to
   `malloc/free/read/view` operations.
2. **Allocator model** — a simulation of glibc tcache/fastbin/unsorted bins for a
   specific glibc version (safe-linking and tcache keys from 2.32 matter).
3. **A version-keyed recipe library + planner** — tcache poisoning → arbitrary
   allocation → `__free_hook = system`, house-of-\*, etc.

Scope realistically to tcache dup/poisoning on glibc 2.27–2.31 first. High effort,
subset coverage; best treated as a long-term track.

## Recommended order

1. ~~Full-RELRO via fmt write to saved return address~~ — DONE (`fmt_writeret.go`).
2. ~~`partialOverwrite` for PIE-without-leak~~ — DONE (`partial.go`).
3. ~~angr strategy for logic/argv/fd~~ — DONE (`angr.go`).
4. Heap — STARTED (`heap.go`: menu-driven UAF fn-ptr overwrite). Remaining:
   tcache poisoning, libc-hook overwrite with a leak, size-prompted allocators,
   and richer menu inference.

## Design invariants to preserve

- **Honesty of the oracle.** A flag counts only when it is disclosed, never when
  it is echoed from input. Every new strategy uses the same extractor.
- **Report, do not bluff.** When a prerequisite is missing (no leak, full RELRO,
  PIE, wrong class), the strategy skips and records a limitation; it never claims
  a solve from a crash.
- **Bounded search.** Every brute force has an attempt cap and honours the context
  deadline; session strategies order the cheap, targeted attempts first.
- **Local analysis, remote action.** Static analysis uses a local copy; the
  session layer carries the exploit to a local or remote target.
