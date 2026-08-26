# rstat

> [!WARNING]
> `rstat` is a performance experiment and eBPF teaching project. It hasn't had
> the compatibility, security, or reliability work required of a production
> system monitor.

`rstat` asks a specific question: can a rich Linux system monitor make frequent
refreshes cheaper by accounting for work when it happens, then reading the
result from userspace?

At a high enough refresh rate, yes. The qualification is that a procfs monitor
pays for each refresh while `rstat` pays on each context switch and again,
more cheaply, for each refresh.
That makes its userspace refresh fast, but its total cost depends on how active
the scheduler is. A quiet machine and a context-switch storm have different
break-even points.

<img src="https://over-yonder.tech/assets/rstat-hero.webp" alt="rstat Waybar tooltip with CPU, memory, task I/O and process rankings" width="100%" />

## What it measures

The eBPF probe maintains per-task counters for:

- on-CPU residency between scheduler switches
- approximate resident memory from the kernel's RSS counters
- task-attributed `read_bytes` and `write_bytes` accounting
- tasks in uninterruptible sleep and process leaders in zombie state

The Rust daemon aggregates threads into processes, computes interval deltas,
adds system metrics from persistent procfs and sysfs file descriptors, and
emits Waybar JSON. The output includes load, CPU use, Linux `MemAvailable` when
readable, memory PSI, swap activity, CPU package temperature where discoverable,
CPU 0 frequency, supported Intel iGPU counters, and top-five CPU, memory, and
task-I/O rankings.

Those terms matter:

- CPU use is non-idle task residency. The kernel-thread toggle controls tasks
  with `PF_KTHREAD`; it doesn't separate user-mode and kernel-mode time inside
  ordinary processes.
- RSS is the kernel's approximate file + anonymous + shared-memory count. For a
  multithreaded process, `rstat` uses the most recently sampled thread instead
  of retaining the largest stale value.
- Task I/O is Linux task accounting, not physical disk throughput. Writes are
  charged when pages are dirtied and may later be cancelled; reads count bytes
  fetched from block-backed storage on a task's behalf.
- A BPF batch lookup isn't an atomic snapshot of the whole machine. Tasks can
  switch while userspace copies the map.
- RSS and I/O for a live task can be up to 10 ms old. Task exit forces a final
  snapshot before the entry is retired.
- A task marked D stays listed until it next runs. A task that has been woken
  but hasn't yet been scheduled can therefore appear blocked briefly.

## How it works

At startup, `rstat` generates `vmlinux.h` from the running kernel's BTF,
combines it with the bundled probe source, compiles it with Clang, and loads the
object from memory. Four scheduler tracepoints maintain the map:

- `sched_process_fork` creates a zero I/O baseline for tasks born after attach.
- `sched_switch` accounts CPU residency and snapshots RSS and I/O for the
  outgoing task. RSS and I/O are limited to one snapshot per task every 10 ms.
- `sched_process_exit` marks a dead process leader as a zombie without dropping
  its final CPU interval and forces a final RSS/I/O snapshot.
- `sched_process_free` marks a task as retired. Userspace consumes its final
  counters once before deleting the map entry, so short-lived tasks don't
  disappear between refreshes.

A one-time procfs scan seeds every pre-existing D-state thread and zombie
process leader. There is no per-refresh process-directory walk.

The userspace side deliberately stays small:

- a custom ELF/BPF loader rather than Aya or `libbpf-rs`
- `BPF_MAP_LOOKUP_BATCH` with preallocated key and value arrays, with an
  iterative fallback
- persistent file descriptors and `pread()` for fixed system metrics
- reused aggregation maps and output buffers
- fixed-size top-five rankings
- a hand-written emitter for the fixed JSON schema

## Measured performance

Measurements below were taken on 2026-07-14 on an AMD Ryzen 5 3600 with 12
online CPUs and Linux 6.18.37. Scheduler activity varied during the review.

`rstat --bench 1000` measured the refresh pipeline from BPF-map read through
JSON construction and retired-entry cleanup. It excludes the potentially
blocking stdout write. Three consecutive runs averaged 0.13–0.16 ms. The
slower representative run was:

| Statistic | Time |
| --- | ---: |
| Average | 0.16 ms |
| Median | 0.15 ms |
| p95 | 0.22 ms |
| p99 | 0.27 ms |
| Minimum | 0.08 ms |
| Maximum | 1.24 ms |

The supported claim is therefore **typically sub-millisecond refreshes**, not
an under-one-millisecond worst-case guarantee.

`rstat --profile 10` builds an instrumented probe. An ordinary review workload
and a deliberate `stress-ng --switch 12` run showed how the continuous cost
changes:

| Workload | Scheduler switches | Handler midpoint | Body time |
| --- | ---: | ---: | ---: |
| Ordinary review load | 12,454/s | 0.641 µs | 7.98 ms/s |
| Deliberate switch storm | 2,363,005/s | 0.767 µs | 1,812 ms/s |

These are histogram-bucket estimates. The timed interval stops before the
profiling map update. It covers the `sched_switch` body, not the less frequent
fork, exit, and free handlers.

### Historical comparison

The original shell script and its raw timings weren't preserved. The project
notes contain incompatible whole-sample and `powerprofilesctl` timings, so the
early totals aren't used as benchmarks here.

Git history does preserve the mechanism: the first Rust version invoked
`powerprofilesctl get` inside its timed sampling path. Replacing that client and
D-Bus round trip with a direct read of
`/sys/firmware/acpi/platform_profile` removed the dominant reported delay.

The final procfs revision is preserved at commit `3123a25`. It enumerated
`/proc`, read `stat` and `io` for ordinary processes, and reported roughly 15 ms
from its internal collection timer. That timer stopped before JSON formatting,
and its original raw samples weren't retained. Rebuilding the exact revision
during the 2026-07-14 review produced 10.3–38.7 ms samples on the same machine
under a different, heavily loaded workload. This confirms the historical order
of magnitude, but it isn't a controlled comparison with the current benchmark.

The supported result is therefore a current 0.13–0.16 ms average userspace
refresh, roughly two orders of magnitude below the historical procfs collection
time.

### The cost model

For a polling monitor:

```text
CPU time per second ≈ refresh cost × refreshes per second
```

For `rstat`:

```text
CPU time per second ≈ handler cost × context switches per second
                    + refresh cost × refreshes per second
```

At the ordinary measured scheduler load, adding a 0.16 ms refresh puts the
estimated `rstat` cost at 8.3 ms/s for a 500 ms interval. A historical 15 ms
procfs poll at that interval costs 30 ms/s. During the deliberate switch storm,
the estimated switch-handler body alone cost 1,812 ms/s, so the poller wins by
a wide margin even at a 100 ms interval. Measure both scheduler activity and
refresh rate on the target machine before choosing the design.

## Building

Requires Linux with BTF, eBPF scheduler tracepoints, task I/O accounting, Nix,
and flakes:

```sh
nix build
```

The Nix package stamps absolute paths to `bpftool`, Clang, and libbpf headers
into the binary. Runtime compilation can take several seconds; it happens once
when the daemon starts.

Loading the programs and opening tracepoint perf events requires `CAP_BPF` and
`CAP_PERFMON` on kernels that support the split capabilities. `CAP_SYS_ADMIN`
also covers the operation, including on older kernels. Running with `sudo` is
the simplest development setup.

## Waybar integration

```jsonc
"custom/sysmon": {
    "exec": "rstat",
    "return-type": "json",
    "restart-interval": 0,
    "on-click": "kill -RTMIN $(pgrep rstat)",
    "on-click-middle": "kill -RTMIN+1 $(pgrep rstat)"
}
```

The default interval is 500 ms. Left-click cycles through 500, 250, 100, 2000,
and 1000 ms. `--ludicrous` selects 16 ms for a terminal or another consumer
that can drain the pipe quickly.

Kernel threads are included by default. Middle-click toggles them for CPU,
blocked-task, and task-I/O aggregation. The footer reports `Kernel threads
included` or `Kernel threads excluded`.

## Benchmarking and profiling

```sh
sudo ./result/bin/rstat --bench 1000
sudo ./result/bin/rstat --profile 10
```

`--bench` measures map collection, system-file reads, aggregation, JSON
construction, and retired-entry cleanup. It doesn't write each result to
stdout.

`--profile` recompiles the probe with self-timing enabled, waits for the given
number of seconds, then prints a log2 histogram. Normal builds contain none of
the second timestamp, bucket calculation, or histogram update.

Both counts must be positive. The two modes can't be combined.

## Known limits

- The three BPF hash maps have a fixed 8,192-entry capacity. Extreme task churn
  between slow refreshes can fill the stats map before retired entries are
  consumed.
- The online CPU set is read once at startup. CPU hotplug after attachment
  isn't tracked.
- Any design that handles every context switch can become expensive during a
  switch storm; the measured stress run used an estimated 1.81 CPU cores for
  the instrumented switch-handler body alone.
- Hardware sysfs metrics vary by machine. Missing sources render as `n/a`.
- Kernel structure support follows the running kernel's BTF, but the code still
  depends on the fields and tracepoints it uses being present.
- The custom loader, signal handling, output path, and broad kernel
  compatibility haven't received production hardening.

## Case study

[Read the condensed performance case study](https://over-yonder.tech/work/rstat.html).
