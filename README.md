# PwnProbe

PwnProbe is a Go CLI for inspecting Linux ELF binaries and collecting evidence from local CTF programs. It provides static inspection, bounded execution, format-string behavior probes, flag extraction, and an automatic solver for simple local challenges (format-string reads, stack-overflow variable/return overwrites, two-argument ret2win ROP, executable-stack shellcode, and ret2libc). Remote sessions and further strategies are planned.

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

## Usage

```sh
pwnprobe inspect --json ./target
pwnprobe run --timeout 1s --input ./input.txt --json ./target
pwnprobe detect --timeout 1s --json ./target
pwnprobe solve --timeout 2s --flag-pattern 'flag\{[^}]+\}' --json ./target
pwnprobe version
```

Use `./bin/pwnprobe` if the binary is not on PATH. Flags precede the target path. `run` sends EOF when no input file is specified. `run` exits nonzero if the target crashes, times out, or exits unsuccessfully; its JSON still records the outcome.

`run` and `solve` accept `--flag-pattern`, a regexp for the flag shape; an empty value uses a broad default (`name{...}`). `run` reports `recovered_flags`: pattern matches present in the output but not in the supplied input. A match that is a substring of the input is treated as echoed and never counted — a program reflecting caller-supplied bytes is not evidence that a secret was discovered.

`solve` runs `detect` first, then tries each applicable strategy and stops at the first payload that yields a non-echoed flag, reporting that exact payload as a reproducible winner. It exits nonzero when no flag is recovered; a crash is never reported as a solve. The target runs in its own directory so a flag file beside it is readable.

- **format_string** (when format-string behavior is confirmed): sends a bounded set of leak payloads (`%p` stack dump, positional `%N$s` reads). Stack-dump output is additionally reassembled from little-endian pointer leaks before matching, so a flag that never appears literally in stdout is still recovered.
- **stack_overwrite** (when the target is an executable PwnProbe can run): brute-forces a line-based overflow, appending each magic constant decoded from the binary's instructions and each function address (on fixed-address, non-PIE binaries) after increasing padding lengths. A flag that then appears in the output recovers both the correct offset and the required value — for example a guard variable that must equal a magic constant, or a redirect to a flag-printing function — without those being hardcoded. For ret2win targets that call into libc, a stack-aligning `ret` gadget is tried to clear the common `movaps` fault.
- **rop_ret2win_args** (when `pop rdi; ret` and `pop rsi; ret` gadgets are present on a fixed-address binary): solves a win function that requires two register arguments equal to specific constants. It first locates the offset and function with sentinel arguments the target echoes, then builds a ROP chain setting RDI and RSI from the binary's decoded constants and calling the function.
- **shellcode** (executable-stack binary that leaks its buffer address): writes shellcode at the buffer, pads to the return address, and overwrites it with the leaked buffer address. **ret2libc** (NX binary that leaks a libc address and has a `pop rdi; ret` gadget): resolves the libc base from the leak, finds `system()` and a `"/bin/sh"` string, and builds a `pop rdi; "/bin/sh"; system()` chain. Both run the target under `setarch -R` so a leaked address stays valid across the baseline and exploit runs, then drive the spawned shell with `cat flag.txt`. This is for local teaching labs, not hardened or remote targets.

Inspection works on Windows and Linux. Execution and detection require Linux; use the Linux build inside WSL on Windows. Probes support x86/x64 executables where the OS provides the necessary loader and libraries.

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

The runner is not a security sandbox. It does not restrict filesystem/network access, memory, CPU, or process count. Use trusted lab programs or run the entire tool in a restricted VM/container. Descendants that escape their process group are outside its cleanup guarantees. Static ELF size guards are not a security boundary for hostile parser inputs.

Probes handle one stdin interaction ending in EOF. Interactive menus, remote transports, gadget analysis, and exploitation strategies are not implemented yet. Files can change between inspection and execution.

## Benchmark engine

The production benchmark engine accepts a caller-provided JSON manifest and requires Linux and GCC:

```sh
pwnprobe benchmark --manifest /path/to/manifest.json --json
```

Each manifest entry contains `name`, `source` (relative to the manifest), `flags`, expected `protections` statuses, and the boolean expectations `format_string`, `crash`, and `timeout`. Optional comparison with the original detector requires `original_baseline: true`, `--original /path/to/pwnpasi.py`, and a caller-provided `--baseline-script /path/to/adapter.py`.

Test code, fixtures, adapters, reports, and compiled binaries are excluded from this repository. The initial local validation passed six controlled fixture cases and the runner/metadata/CLI checks. An easy local format-string challenge was detected and a manually supplied flag-read input succeeded ten times; the patched control did not disclose the flag. These results are not a general exploit-success benchmark.

## Roadmap

Restricted execution backend; held-out challenge evaluation; interactive local/remote sessions; debugger evidence for crash classification; further solve strategies (runtime-leak parsing for shellcode-on-stack and ret2libc, menu-driven protocols, PIE targets via a leak) behind explicit prerequisites; outcome verification across strategies.

The project is an independent Go rebuild inspired by [PwnPasi](https://github.com/heimao-box/pwnpasi). Licensed under MIT.
