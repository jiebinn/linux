# Inherited group loss accounting

## Value and scope

This experiment reproduces an incorrect read of PERF_FORMAT_LOST when
PERF_FORMAT_GROUP and inheritance are enabled. A successful read can report
zero losses despite hundreds of lost samples. This breaks collection-quality
checks in raw perf/libperf clients using this ABI. Modern perf inherited group
sampling also requests GROUP and LOST; see shell attr group-sampling1/2 tests
for kernels >= 6.12.

This does not imply that every perf record invocation hides losses.
PERF_RECORD_LOST records can still expose the problem, and a direct perf record
end-to-end failure has not been demonstrated here. Lost reads also matter when
a full ring at capture end never publishes a trailing LOST record.

## Root cause and candidate

perf_read_group() allocates a zeroed output buffer and invokes
__perf_read_group_add() for the root and each inherited group. Counts use +=;
lost counts used =, allowing an inherited zero to erase the root's losses.
The two-line fix accumulates leader and sibling losses without changing
structures, ABI, event generation or command syntax.

Inherited ring output already charges losses to its parent before incrementing
lost_samples. The bug is the later overwrite, not missing child loss charging.
Introduced by 119a784c8127, "perf/core: Add a new read format to get a number of
lost samples".

## Reproduce

```sh
# Select an online CPU allowed by your affinity/cpuset.
python3 tools/perf/Documentation/experiments/inherited-group-lost/check.py --cpu 400
```

The driver compiles the helper with -Wall -Wextra -Werror, uses sudo -n, and
prints a nine-trial JSON matrix. It needs perf_event_open software sampling,
PERF_FORMAT_LOST support and permission. Missing support, sampling or losses is
an inconclusive setup failure, not a pass. It returns 1 when a read disagrees
with the stream, and should return 0 on a corrected kernel.

The parent pins to one CPU and creates a two-event group with a one-page ring.
A forked child holds an inherited group alive without running a hot workload.
The parent samples for 200 ms without draining, disables, drains, then samples
briefly to flush the pending loss record. It compares read losses while the
child is alive and after exit. Only group/inherit settings vary in the controls.
The non-group mode still creates a group but reads the leader individually.

Optional independent inspection with bpftrace (requires BTF/kprobe support):

```sh
sudo bpftrace tools/perf/Documentation/experiments/inherited-group-lost/lost_read_probe.bt
```

In another terminal, compile lost_group.c and run it with `1 400 1`. Stop the
probe afterwards. No kernel installation is performed by these programs.

## Observations on the existing kernel

Host: 6.19.0-rc7-upstream+, CPU 400. Packaged source was rerun on 2026-10-28:
three inherited group cases failed, six controls passed (expected driver rc=1).
The earlier saved results are lost-group-results.json and
lost-repeat-results.json, with three runs per mode:

| Mode | Stream loss | read loss |
| --- | --- | --- |
| Group + inherit | 453..458 | 0 in every run |
| Individual read + inherit | 453..458 | matches stream |
| Group without inherit | 455..458 | matches stream |

lost-read-probe.txt and lost-read-probe-case.json independently show the helper
reading a root loss of 461 followed by an inherited zero; userspace receives 0.
The after-exit read also returned zero in these trials. This observation is not
a guarantee about all child-exit/context-swap cases.

## Verification and remaining gates

- Production fix passes strict checkpatch with 0 errors/warnings/checks.
- Modified kernel/events/core.o builds with W=1 and no compiler warnings/errors.
- Driver and C helper compile/run; its assertions detect the current defect.
- **The candidate kernel has not been booted. Runtime repair is not yet tested.**
- Before upstream submission, run the matrix on the candidate and exercise
  sampling siblings, multiple inherited groups, child exit, ID/time fields,
  and non-inherited reads. The present sampling fixture tests leader loss.
- Kernel installs/reboots and mailing-list submission require separate work.

Pinned base: perf-tools-next e74880764bf94b738102b4b6b6e8304d0c8375d3, still
current after fetch on 2026-10-28. Checked master d135ab453a7400a34930bdda1ef4bdc8acfac80e
and tip/perf/core f5a78ecccd98a04c47cea1cd63c2a2fdce8a4b48 retain the assignments.
Unmerged mailing-list search is incomplete; no claim is made that nobody has
previously proposed a fix.

The evidence commit is separate from the production fix and has no installed
command or build integration. Disabling inheritance or reading individually
is a workaround that changes the collection scope or read interface.
