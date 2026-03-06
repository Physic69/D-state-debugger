# cvmfs-debug-rescue

A tool for extracting diagnostic information from processes stuck in
uninterruptible sleep (D-state), where standard debugging tools like `gdb`,
`ptrace`, `gcore`, and `kill -9` do not work.

Tested on Arch Linux, kernel 6.x, GDB 17.1.

---

## The Problem

FUSE filesystems can deadlock. When the FUSE daemon hangs — due to network
timeouts, lock contention, or bugs — every process accessing the filesystem
enters D-state (`TASK_UNINTERRUPTIBLE`). These processes:

- Cannot be killed (not even with `SIGKILL`)
- Cannot be debugged with `gdb` (ptrace requires signal delivery)
- Cannot be core-dumped with `gcore` (uses ptrace internally)
- Cannot be forced to dump core via `kill -ABRT` (signal sits in queue)

Every standard debugging tool assumes the process will respond to signals.
A D-state process will not.

## The Solution

This tool constructs a valid ELF core dump by reading directly from
`/proc/<pid>/` interfaces, which remain accessible even for D-state
processes. No ptrace, no signals, no process cooperation required.


```

/proc/<pid>/                    ELF Core File
┌─────────────┐                ┌──────────────┐
│ syscall      │──► registers ──►│ NT_PRSTATUS  │
│ (RIP,RSP,   │   (per thread) │ (per thread) │
│  RDI,RSI..) │                │              │
├─────────────┤                ├──────────────┤
│ cmdline      │──► proc name ──►│ NT_PRPSINFO  │
│ status       │                │              │
├─────────────┤                ├──────────────┤
│ maps         │──► file map  ──►│ NT_FILE      │
│              │                │              │
├─────────────┤                ├──────────────┤
│ auxv         │──► dyn linker ─►│ NT_AUXV      │
│              │                │              │
├─────────────┤                ├──────────────┤
│ mem          │──► raw memory ──►│ PT_LOAD      │
│              │   (per region) │ segments     │
└─────────────┘                └──────────────┘
│
▼
gdb binary core
(gdb) bt
Full stacktrace

```

## Key Finding

**`/proc/<pid>/mem` is fully readable for D-state processes.** The kernel does
not block these reads because they access page tables directly, bypassing the
signal delivery mechanism that ptrace depends on.

This was not previously documented clearly for D-state FUSE processes.

## Quick Start

```bash
# Build
make

# Create a test environment
mkdir -p /tmp/testmount
./toy_fuse -f /tmp/testmount &

# Trigger a D-state process
stat /tmp/testmount/hang &
kill -9 $!
# Process is now unkillable and undebugable

# Extract core dump
sudo ./cvmfs_debug_rescue $! /tmp/rescue.core

# Analyze
gdb /usr/bin/stat /tmp/rescue.core
(gdb) bt
#0  statx (...) at ../sysdeps/unix/sysv/linux/statx.c:28
#1  do_stat (...) at src/stat.c:1361

```

## What Standard Tools Show vs This Tool

Standard tools on a D-state process:

```
$gdb -p 6612            # hangs indefinitely$ gcore 6612             # hangs indefinitely
$kill -9 6612           # no effect$ kill -ABRT 6612        # no effect, no core dump

```

Kernel-side info (always available but limited):

```
$ sudo cat /proc/6612/stack
[<0>] request_wait_answer+0x1d0/0x260
[<0>] __fuse_simple_request+0x120/0x310
[<0>] fuse_lookup_name+0xc3/0x210
...

```

This shows the kernel stack but not the userspace context.

**This tool:**

```
$sudo ./cvmfs_debug_rescue 6612 /tmp/rescue.core$ gdb /usr/bin/stat /tmp/rescue.core

#0  statx (fd=-100, path="/tmp/testmount/hang", flags=2304,
    mask=4095, buf=0x7ffe1fecd310)
    at ../sysdeps/unix/sysv/linux/statx.c:28
#1  do_stat (...) at src/stat.c:1361

```

Full userspace context with source file, line number, and function arguments.

## Tools Included

| Tool | Purpose |
| --- | --- |
| `cvmfs_debug_rescue` | Core dump constructor for D-state processes |
| `probe_proc` | Verifies `/proc` readability for D-state processes |
| `toy_fuse` | FUSE filesystem with intentional hang points for testing |

## /proc Readability for D-State Processes

All tested `/proc/<pid>/` interfaces remain accessible:

| File | Readable | Content |
| --- | --- | --- |
| `status` | Yes | Process state, UIDs, memory info |
| `maps` | Yes | Virtual memory layout |
| `mem` | Yes | Raw process memory contents |
| `stack` | Yes | Kernel stack trace |
| `wchan` | Yes | Wait channel (kernel function name) |
| `syscall` | Yes | Current syscall number + register state |
| `auxv` | Yes | ELF auxiliary vector |
| `cmdline` | Yes | Command line arguments |
| `task/` | Yes | Thread enumeration and per-thread state |

## Register Extraction

`/proc/<pid>/syscall` provides more information than commonly documented:

```
Format: syscall_nr arg0 arg1 arg2 arg3 arg4 arg5 RSP RIP

On x86_64, syscall arguments map to registers:
  arg0 = RDI    arg1 = RSI    arg2 = RDX
  arg3 = R10    arg4 = R8     arg5 = R9

This gives us 8 register values (RDI, RSI, RDX, R10, R8, R9, RSP, RIP)
from a single procfs read, without ptrace.

```

## Limitations

**Shallow backtrace (1-2 frames).** `/proc/<pid>/syscall` does not expose
RBP or callee-saved registers (RBX, R12-R15). GDB's stack unwinder needs
these for deep unwinding, especially with `-fomit-frame-pointer` (the gcc
default). The freeze point and immediate caller are always resolved correctly.

Possible solutions for deeper unwinding:

* Kernel module exposing `task_pt_regs()` (full register set)
* eBPF-based register capture via `bpf_get_task_stack()`
* DWARF-based unwinding using `.eh_frame` with only RIP and RSP

**Thread stack reading.** Thread stacks allocated by libpthread reside in
large anonymous memory regions that include guard pages. The current memory
reader may fail on guard pages and zero portions of these regions. This
affects daemon-side multi-thread dumps. Client-side single-thread dumps
work correctly. Fix identified: per-chunk seeking instead of sequential
reading.

**x86_64 only.** Register layout and ELF note structures are hardcoded for
x86_64 Linux.

## Relevance to CVMFS

CVMFS is a FUSE filesystem used across the WLCG computing grid to distribute
experiment software. When the CVMFS daemon hangs — network timeout to Stratum
servers, cache corruption, lock contention — batch jobs accessing `/cvmfs/`
enter D-state silently.

This tool enables site administrators to:

1. Identify which syscall a stuck process is frozen in
2. See the userspace code path that triggered it
3. Dump the CVMFS daemon's thread states
4. Generate actionable bug reports with full stack traces

Potential integration points:

* Ship as a companion diagnostic tool alongside CVMFS
* Embed a watchdog thread for automatic hang detection and state export
* Add eBPF probes for live FUSE request monitoring
* Include in CVMFS debugging documentation as a cheat sheet

## Future Work

* [ ] Per-chunk memory reading for thread stack regions
* [ ] Multi-thread daemon dump verification
* [ ] eBPF-based FUSE request monitoring (catch hangs as they happen)
* [ ] Embedded watchdog with shared memory state export
* [ ] DWARF-based stack unwinding for deeper backtraces
* [ ] Testing against actual CVMFS installations
* [ ] Debugging cheat sheet for CVMFS documentation

## Requirements

* Linux x86_64 (kernel 5.x+)
* Root access (for `/proc/<pid>/mem`)
* `libfuse3-dev` (for `toy_fuse` only)
* GDB with debuginfod support (for automatic symbol resolution)

## Building

```bash
make          # builds all three tools
make clean    # removes binaries

```

## Documentation

* [How It Works]() — development process and technical details
* [Example Session]() — full terminal output showing the tool in action

```

```