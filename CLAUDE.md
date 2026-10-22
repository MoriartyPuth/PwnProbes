# PwnProbes — working notes for Claude Code

PwnProbes is a Go CLI for inspecting Linux ELF binaries and recovering flags from
local or remote CTF programs (static inspection, bounded execution, format-string
probes, and an automatic solver). It is authorized security-research / CTF
tooling.

This file orients a fresh session. For current roadmap progress, read
[`docs/ROADMAP_STATUS.md`](docs/ROADMAP_STATUS.md); for the full source plan, read
[`docs/HYBRID_FRAMEWORK_ROADMAP.md`](docs/HYBRID_FRAMEWORK_ROADMAP.md).

## Build and test

```sh
go build ./...
go test ./...            # platform-independent unit tests (no target execution)
go test -race ./...      # run before every commit
```

- Requires Go >= 1.23 (see `go.mod`). No third-party module dependencies.
- `internal/runner` and `internal/session` only execute targets on **Linux**. On
  macOS the native-execution paths and their integration tests skip, and no
  end-to-end `solve` runs — use a Linux machine to validate real solves.
- End-to-end lab/benchmark suite lives in a separate repo:
  `github.com/MoriartyPuth/PwnProbe-benchmarks`.
- The `angr_logic` strategy needs `python3` with `angr` (`PWNPROBE_PYTHON` to
  select the interpreter); it is skipped when absent.

## Layout

- `cmd/pwnprobe` — CLI (`inspect`, `run`, `detect`, `solve`, `strategies`,
  `benchmark`, `version`).
- `internal/inspect` — static ELF facts. `internal/detect` — format-string / crash
  probes. `internal/extract` — echo-aware flag extraction.
- `internal/runner` — bounded one-shot execution. `internal/session` — interactive
  transport (local subprocess or remote TCP).
- `internal/execution` — `Executor`/`Session` facade over runner+session.
- `internal/solve` — the solver: `Strategy` interface + legacy wrappers, a single
  `registry` with capability filtering and deterministic cost-based ranking, plus
  the report (environment, per-strategy timing, plan, rejections).
- `internal/rop` — ROP gadget catalog, register solver, chain assembler.
- `docs/ARCHITECTURE.md` — design and the exploitation-class roadmap.

## Conventions

- One branch per roadmap PR (`feat/...` or `fix/...`), each reviewable and
  behavior-preserving unless its message says otherwise. PRs 2+ are stacked/merged
  into `main` in order.
- **Never add Claude/AI attribution** to commits or PRs (no `Co-Authored-By:
  Claude`, no "Generated with Claude"). Commit under the repo's own git identity.
- Keep the flag oracle honest: a flag counts only when disclosed and absent from
  the input that produced it; a crash is never a solve.
- Run `go build ./...`, `go vet ./...`, and `go test -race ./...` before committing.
