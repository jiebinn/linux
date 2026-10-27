# RFC evidence: identify inherited CPU quota constraints

This package records an experimentally demonstrated missing measurement
capability. It adds no installed perf command and changes no perf build,
legacy command path or structure. The scripts are experiment scaffolding,
not a production perf implementation.

## The practical problem

A container task can have long runnable waits even when its own cgroup
has `cpu.max = max 100000` and `cpu.stat nr_throttled = 0`: an ancestor
may have exhausted its CPU quota. Looking only at that container's
configuration and counters misses the effective constraint.

Perf sched reports task scheduling delays, but does not connect each wait
to a timeline of CPU quota constraints and identify the limiting ancestor.
Manually reading every ancestor's counters can identify aggregate
throttling; it cannot establish which recorded waits overlapped it. Perf's
cgroup event filtering does not supply this timeline either. This is a
specific gap in perf sched; no claim is made that every other tracing tool
lacks cgroup throttling diagnostics.

The question to answer is: **which of this task's waits overlapped CPU
quota constraints, which ancestor supplied them, and for how long?**
It is a measurement capability, not a different arrangement of delay rows.

## Controlled observation

Measured on 2026-10-27, Linux 6.19.0-rc7-upstream+, 512 logical CPUs,
bpftrace 0.24.2. One CPU-bound task is pinned to CPU 400 for approximately
two wall-clock seconds. Each case uses new private parent/child cgroups;
only the workload is placed in the child. Both capture streams use
CLOCK_MONOTONIC. The three cases change where the CPU limit is applied.

| Case | Parent cpu.max | Child cpu.max | Maximum completed runnable wait | Child nr_throttled delta | Parent nr_throttled delta | Wait overlap with observed quota constraints |
|---|---|---|---:|---:|---:|---:|
| Unlimited | max 100000 | max 100000 | 0.024 ms | 0 | 0 | 0% |
| Parent limited | 20000 100000 | max 100000 | 80.811 ms | 0 | 21 | 99.9749% |
| Child limited | max 100000 | 20000 100000 | 80.615 ms | 21 | 0 | 99.9721% |

In the parent-limited case, completed runnable waits total 1635.324 ms;
1634.914 ms overlaps the parent's observed throttle intervals. No child
throttle intervals are observed. Thus checking only the child misses the
constraint despite the long waits. Removing the quota reduces the maximum
wait to 24.419 us in this controlled run.

This is one hierarchy trial, not a benchmark distribution or evidence of
application performance improvement. Separate earlier single-cgroup
trials in both case orders motivated this experiment; their recordings
are not included here. Non-overlapping wait time is **not** automatically
CPU contention. Timestamp overlap alone does not measure the latency an
application would save if its quota were removed.

## Review the evidence without root

From this directory, with Python 3.8 or later:

```sh
python3 report.py fixture --throttle-events fixture/throttle-events.txt \
  > /tmp/quota-replay.json
python3 - <<'PY'
import json
from pathlib import Path
assert json.loads(Path('/tmp/quota-replay.json').read_text()) == \
       json.loads(Path('fixture/reference.json').read_text())
print('Replay matches the measured reference')
PY
python3 report.py fixture --throttle-events fixture/throttle-events.txt \
  --include-waits > /tmp/quota-waits.json
```

`--include-waits` shows each completed R-state switch-out to switch-in
interval, its overlap with the union of relevant throttle intervals,
and the parent/child contributors. Contributor overlaps can overlap
one another and must not be summed; the effective value uses their union.
No wakeup-wait reconstruction is implemented in this experiment.

The fixture is a minimized, sanitized excerpt of the measured recordings:

- only switch events involving the pinned task are retained;
- task IDs, unrelated task names/IDs, cgroup paths/IDs and kernel runqueue
  addresses are replaced with stable labels;
- one constant offset is subtracted from all timestamps;
- durations, state flags, quotas, measured counters and affinity are kept.

`reference.json` is the original numerical result with those identities
rewritten. It is a replay check, not proof of capture completeness. No
binary perf.data or full host event stream is included. The parser cannot
detect an entire missing throttle/unthrottle pair or switch-out/switch-in
pair, and sanitized excerpts cannot certify the absence of event loss.

## Reproduce on a supported host

Requires root, cgroup v2 with the CPU controller already enabled at the
root, kernel BTF, bpftrace, perf and Python. These probes access internal
kernel functions and structures; they were validated only on the kernel
above and may fail or need adaptation on another kernel. Do not interpret
missing probe output as evidence of no throttling.

Choose an online CPU available to the runner. In terminal 1, start the
tracer and wait for `READY` before using terminal 2:

```sh
sudo timeout -s INT 30s bpftrace -q -B line throttle.bt 400 \
  > throttle-events.txt 2> tracer.err
```

In terminal 2:

```sh
mkdir quota-capture
sudo python3 run.py --cpu 400 --perf /path/to/perf \
  --output-dir quota-capture
for case in unlimited parent-limited leaf-limited; do
  sudo /path/to/perf script -i "quota-capture/$case.data" \
    --ns --show-lost-events -F trace:cpu,time,event,trace \
    > "quota-capture/$case-events.txt" \
    2> "quota-capture/$case-decode.err"
done
```

Wait for terminal 1 to finish before reporting; timeout exit 124 is
expected. Inspect `tracer.err`, the record/decode logs and event streams
for failures or dropped events. Then:

```sh
python3 report.py quota-capture --throttle-events throttle-events.txt \
  --include-waits > quota-capture/results.json
```

`run.py` uses PID-specific temporary cgroup names, rejects existing groups
and nonempty output directories, and removes only groups it created. It
does not change root controller configuration. Precreate the output
folder as the reporting user so decoded output can be written there;
perf captures and workload metadata will be owned by root. Raw tracer
output contains kernel addresses: sanitize it before sharing.

The workload records its affinity, parent/child IDs and quotas, monotonic
start/end timestamps, CPU time and counter deltas before group removal.
The tracer records successful throttle/unthrottle return transitions.
Probe-return timestamps approximate state transitions; they are not an
exact replacement for cpu.stat accounting. The tracer must cover the
whole experiment, including the final unthrottle transitions.

## Proposed production capability and development gates

A future implementation should associate individual waits with the
**effective** CPU quota constraint timeline, including ancestry:

- report observed wait boundaries, origin and relevant group identities;
- calculate overlap without charging another CPU's cgroup runqueue;
- identify constraining ancestors without double-counting nested limits;
- expose unknown portions when observation coverage is insufficient;
- report residual time without automatically assigning a cause.

Keep new collector/report state separate from legacy perf sched state.
Do not add fields to existing sched structures for this investigation.
PR #11's isolated waits prototype is a separate prerequisite option;
this experiment does not claim to complete its remaining correctness gates.

Before writing or proposing production perf code:

1. Validate concurrent parent/child constraints and siblings sharing a
   parent budget; verify interval unions and ancestor identification.
2. Validate multiple CPUs and migrations, task/group lifetimes and
   dynamic membership or quota changes. An ancestor's throttle events
   on another CPU must not be charged directly to this task.
3. Validate missing boundaries, reordered/lost events and capture startup
   or stop gaps. Balanced observed pairs alone are insufficient.
4. Run schbench or netperf with controlled quotas and measure application
   tail latency, rather than only the busy-loop task's runnable waits.
5. Measure capture overhead and bounded-memory behavior; assess existing
   tools and stable tracepoints before choosing a collector architecture.

The current report deliberately accepts only one pinned task/CPU per
case, a static two-level hierarchy and completed R-state waits within the
workload window. It rejects observed unbalanced throttle transitions and
visible PERF_RECORD_LOST markers. It does not provide general trace-loss
certification, general wakeup analysis or automatic causal attribution.

A bounded online collector may eventually avoid large perf.data files and
repeat sorting. That is an architecture candidate, not a demonstrated
performance result of this package. If the correctness or usefulness gates
fail, stop or change direction rather than build a new view around them.
