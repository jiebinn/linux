# BPF lock workload filtering regression

## Value and scope

`perf lock contention -b -- command` can include contention from unrelated
processes even without -a. On a busy machine this corrupts the scope of a
targeted lock investigation. The candidate restores the workload task filter,
fixing a regression rather than adding another report format.

The fix changes two lines in util/bpf_lock_contention.c. No kernel/common
structures, ABI, BPF map layout or command syntax change.

The original filtering implementation (6fda2405f414) enabled has_task for a
workload and inserted its PID in task_filter. Moving control data from bss to
rodata in 4afdc00c378f removed that enable operation. The workload PID is still
inserted after load, but has_task was only set for explicit task targets.
Set it before BPF load, under the same condition as the workload map insertion.

## Reproduce and compare

Build baseline and candidate perf with BPF skeleton support, then:

```sh
python3 tools/perf/Documentation/experiments/lock-workload-filter/check.py \
  --baseline /path/to/baseline/perf --candidate /path/to/candidate/perf \
  --cpus 400,401,402,403
```

Choose four online CPUs allowed by affinity/cpuset. The driver compiles small
helpers in a temporary directory and invokes perf using sudo -n. It needs
lock contention tracepoints, BTF, BPF loading permission, symbol access and
mmap_lock symbol support. It runs these four modes on both binaries:

1. Quiet workload plus an independent four-thread mprotect contention source.
2. Contending workload whose main TID also runs mprotect, plus background noise.
3. Explicit -a collection of background contention (positive control).
4. Explicit --pid of the already threaded background workload (positive control).

The baseline must reproduce contamination. The candidate must exclude
background rows in modes 1/2, keep target main-TID rows in mode 2, and keep
positive control rows in modes 3/4. Empty controls or collection errors are
inconclusive, never interpreted as a successful fix. JSON includes commands'
stdout/stderr and workload results. A one-second attachment delay is a timing
assumption, not a readiness API; slow systems may need a larger window.

The initial shorter-delay run was inconclusive because its baseline --pid
control was empty. It was not counted as a passing run. The final run uses
longer collection/workload windows. Baseline/candidate results are in
fix-validation.json.

## Earlier scope evidence

baseline-results.json records the original experiment on 6.19.0-rc7-upstream+,
CPUs 400..403, software version 7.3.g5fbb20f3420e. The lock files in that build
are identical to pinned upstream e74880764bf9 (its local fix only affects sched).
A quiet non-sleep command collected 31 unrelated worker contention events.
The final comparison uses the same unchanged lock baseline and a newly built
candidate perf.

The staged_target.c helper and lock-staged-results.json also demonstrate an
additional limitation: --pid snapshots TIDs and omits threads created later.
Two --pid trials had no worker rows; -a controls captured 12 and 7 waits.
A later repetition captured 22 and 26 waits with -a but again none with --pid.
Existing-before-attach workers were captured by --pid. These are controlled
kernel-lock workloads, not a claimed production-service incident rate.

## Important limitation: this is a TID-filter repair

The candidate restores the original workload main-TID scope. It does not
implement process-wide TGID filtering, newly created threads or descendants.
A threaded workload can therefore lose worker rows that the broken unfiltered
collector happened to include. That broader capability should be designed
explicitly, separating --pid/--tid semantics and testing exec, exit, PID reuse,
map failures and combinations with CPU/cgroup filters. perf off-CPU BPF has a
TGID filtering pattern worth reusing.

The simple fix is independently reviewable as a regression repair; it must not
be advertised as a complete process-tree tracking feature. -a and explicit
cgroup isolation remain alternatives; fixed --tid lists omit future workers.

## Upstream and verification

Pinned perf-tools-next e74880764bf94b738102b4b6b6e8304d0c8375d3 remains current
after fetch on 2026-10-28. Checked torvalds/master
d135ab453a7400a34930bdda1ef4bdc8acfac80e retains the broken workload path.
Unmerged mailing-list search is incomplete; absence of a merged fix does not
prove absence of a previous proposal.

The candidate perf builds with BPF skeletons, production fix passes strict
checkpatch (0 errors/warnings/checks), and git diff --check passes. Runtime
comparison results are recorded separately. No kernel installation or reboot
is needed for this userspace repair.

The evidence commit is separate and has no installed-command/build integration.
Portable upstream regression coverage and complete latest mailing-list overlap
checks remain gates before formal upstream submission.
