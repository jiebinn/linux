# RFC: avoid unused data-mapping notification work during profiling

## Practical problem and value decision

Profiling a workload can change its behavior enough to obscure the original
bottleneck. On this 512-CPU host, ordinary per-CPU recording of four busy
mprotect workers made perf's own event traversal the dominant sampled
kernel function. The mappings were non-executable, data mapping recording
was disabled, and the traversal generated no useful MMAP records for them.

The opportunity is to avoid this unrequested kernel work while preserving
the event layout, inheritance and executable mapping metadata. This is an
existing collection performance problem, not a new report view. The draft
kernel change adds nine lines, one global interest counter and an early
return. Existing structures, perf commands and output formats are unchanged.

A useful existing workaround is `perf record --per-thread`. It reduces the
number of events in each task context, but also disables inheritance and
is ignored with -a/-C. It therefore does not preserve every existing
collection scope. A kernel interest check can benefit existing collectors
without requiring that tradeoff or a new CLI option.

## Evidence on the running kernel

Measured on 2026-10-27, Linux 6.19.0-rc7-upstream+, two sockets, 512 online
CPUs. Four independent processes each run one worker on CPU 400..403 for
1.5 wall-clock seconds, repeatedly toggling a private 4 KB anonymous
mapping between read-only and read/write. No executable mappings change.

The simplified sampler opens cycles:k events at 199 Hz for the four worker
TIDs. It holds the CPU event layout, ring buffers, sample fields, comm/task
notifications and workload constant, changing only attr.mmap/mmap2 from
1 to 0. attr.mmap_data stays 0. No callchains or inherited children are
collected by this isolated sampler.

| Event layout | MMAP enabled | Events | Median operations, three runs | Sample counts | Lost samples | MMAP records |
|---|---:|---:|---:|---|---:|---:|
| Per CPU | yes | 2048 | 1,887,242 | 1205..1207 | 0 | 0 |
| Per CPU | no | 2048 | 7,415,498 | 1206 | 0 | 0 |
| Per thread | yes | 4 | 7,018,391 | 1206..1208 | 0 | 0 |
| Per thread | no | 4 | 7,569,275 | 1204..1206 | 0 | 0 |

The order is 1,0,0,1,1,0 for each layout. The per-CPU no-MMAP contrast
completes 3.93 times as many operations. With four per-thread events the
contrast is 1.08 times. This isolates a cost amplified by event-context
size; disabling MMAP did not remove needed mapping records in this test.
These are not patched-kernel performance results.

A separate full perf record run (`cycles:k`, 199 Hz, callchains) showed
89.08% self overhead in perf_iterate_ctx for the private-process workload.
Using --per-thread changed the profile and substantially improved
throughput. Profile excerpts (with trailing spaces removed) are supplied for inspection. They are short
instrumented runs, not estimates of the application's uninstrumented
CPU distribution. The isolated interest-flag comparison above is the
stronger causal contrast. A packaged two-trial rerun also confirmed the
contrast and zero lost/MMAP records; its exact values are not the reference
three-trial medians.

## Why the source supports the hypothesis

perf_event_mmap_match() accepts a non-executable VMA only for an event with
attr.mmap_data. The existing global nr_mmap_events count combines ordinary
and data mapping interests. Consequently perf_event_mmap() can prepare a
mapping notification and iterate contexts even when no event can accept
that class of mapping. The rejection happens at each event's callback.

The proposed nr_mmap_data_events counter follows the existing root-event
accounting lifetime. Inherited events retain the parent's interest in the
same way as nr_mmap_events. The early return applies only to a
non-executable VMA with no data-mapping interest. perf_addr_filters_adjust()
already ignores non-executable VMAs because data address filtering is not
supported there. Executable mapping and requested data mapping paths
retain their existing processing.

The intent is to avoid the unnecessary work illustrated by the flag
contrast while keeping normal executable mapping listeners enabled.
Disabling all MMAP is an experimental control, not the proposed API or a
recommended general profiling configuration.

## Reproduce the controlled contrast

Requires Linux perf_event_open access, sudo without a password for this
runner, a C compiler and Python. Choose four distinct allowed CPUs. The
per-CPU experiment assumes dense online CPU IDs 0..CPU_COUNT-1 and opens
four times CPU_COUNT events, with 8-page rings per event. On the measured
host this is 2048 FDs and approximately 72 MiB of ring mappings. The sampler
raises its own soft FD limit within its existing hard limit.

From this directory:

```sh
cc -O2 -Wall -Wextra -pthread workload.c -o workload
cc -O2 -Wall -Wextra sampler.c -o sampler
python3 run.py --cpus 400,401,402,403 --cpu-count 512 \
  --rounds 3 --output repeat.json
```

Use `--cpu-count 0` to repeat the four-event per-thread contrast.

The runner reverses case order between pairs, uses private anonymous
mappings and kills its own workload group on failure. It rejects an
existing output file. The references contain aggregate results and no
kernel addresses, task IDs or binary perf.data. The workload and sampler
are experiment scaffolding, not installed perf programs.

## Verified and remaining gates

Verified:

- Three-run interest-flag contrasts for both layouts, with zero observed
  sample loss and zero MMAP records in each case.
- Full perf profile identifies the event traversal; the existing
  --per-thread workaround was tested and acknowledged.
- The packaged reproduction scripts and C programs build, and a fresh
  two-trial packaged capture succeeds.
- The modified kernel/events/core.o builds on the pinned baseline with
  the running kernel's config normalized by olddefconfig. Compiler output
  has no warnings; config migration warned about two old symbol values.
- diff/checkpatch checks for the code change.

Before treating the patch as ready:

1. Run baseline/candidate kernels with identical full perf collection and
   native workload controls. Do not substitute the no-MMAP contrast for
   a measurement of the patch's benefit.
2. Verify executable MMAP/MMAP2 records and anonymous/file-backed data
   MMAP records when mmap_data is requested, including simultaneous
   listener classes and another process's data listener.
3. Verify fork/inherit, event open/close/error paths and concurrent
   listener lifetime changes; compare record contents as well as counts.
4. Check AUX executable address filters, current architectures and newer
   kernels for assumptions about non-executable mappings.
5. Validate at least one allocator/JIT or other mapping-heavy application,
   and scaling with CPU count/event count. The present tests are controlled
   syscall workloads and establish no production prevalence.

No kernel was installed or booted for this investigation. Current source
compile success does not establish runtime or recording correctness.

## Alternative investigated: rwsem spin coverage

The investigation began with rwsem optimistic acquisition missing from
lock:contention events. In one shared-mm capture the existing perf lock
writer count matched 58 visible waits; independent probes observed another
423,348 successful write slowpaths with no matching contention interval.
Private address spaces removed those slowpaths. Existing perf CPU sampling
also identified osq_lock/rwsem_spin_on_owner, so a new standalone spin view
is not justified by that experiment alone.

That instrumentation coverage question is retained as a lower-priority
candidate. The mapping-notification cost above provides a more direct
opportunity to improve existing collection, with a much smaller change.
