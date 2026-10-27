# Value assessment before production development

## Decision

Archive this opportunity rather than continue production development.
The present evidence does not establish sufficient incremental diagnostic
value over existing interfaces to prioritize more research. No real
application incident requiring the proposed correlation has been shown.
The mechanism can matter to quota-constrained latency-sensitive services,
but that alone does not justify another tool.

The inherited-quota mechanism is documented kernel behavior. Reproducing
it does not itself establish a new tool's value. The useful addition would
be identifying the quota constraints affecting specific long task waits
when aggregate observations cannot answer the operational question.

## What is already available

| Existing method | What it answers | Remaining limit for this investigation |
|---|---|---|
| Task cgroup ancestry and each ancestor's cpu.max | Which groups have configured bandwidth limits | Does not establish that a particular wait encountered an exhausted budget |
| cpu.stat at each relevant level | Aggregate own-bandwidth throttling counters | Does not match a task wait to its effective constraint |
| cpu.stat.local | Actual local-runqueue throttling time, potentially including inherited throttling | Cumulative, across the group's runqueues; no per-task interval or limiting-ancestor identity |
| cAdvisor/Prometheus CFS throttle metrics | Aggregate throttling trends useful for monitoring and first diagnosis | Group totals do not explain a specific task's long wait |
| perf sched; BCC runqlat/cpudist | Scheduling delay or CPU/off-CPU interval distributions | The inspected commands do not join those intervals to ancestor bandwidth constraints |

The kernel documentation and implementation explicitly distinguish
cpu.stat from cpu.stat.local. Zero nr_throttled alone is therefore an
insufficient check, not proof that inherited throttling is undetectable
with existing interfaces. A simpler counter-based diagnosis should be
the first step in a real incident.

The BCC source check covers runqlat and cpudist, not every BPF tool. A
complete existing-tool comparison remains a gate. If an available tool
already supplies reliable per-wait ancestry correlation, extending or
documenting that tool may be preferable to a new perf implementation.

## Applicable real deployments

| Deployment | Required condition | Useful operational decision |
|---|---|---|
| Kubernetes latency-sensitive service | Effective CPU bandwidth limit at container, Pod or another ancestor; enforcement enabled | Determine whether specific service-thread waits encounter quota constraints before changing CPU limits or investigating scheduler placement |
| systemd services within a slice | CPUQuota on the service or ancestor slice | Find whether a shared slice budget constrains a service whose own quota is unlimited |
| Multiple containers or workers sharing a capped parent | Concurrent siblings consume the parent budget | Establish that a latency-sensitive worker encounters the shared constraint; sibling budget-consumer attribution needs additional accounting |
| CPU-limited database, RPC or event-loop service | Long runnable waits matter to measured application latency | Correlate the affected thread's waits and constrain further investigation; request critical-path attribution requires application timestamps |

These are mechanism-based use cases, not deployment frequencies or tested
application results. The experiment validates none of the Kubernetes,
systemd-manager or application integrations above.

CPU requests/weights alone are not CPU bandwidth limits. A Kubernetes
namespace ResourceQuota is an admission/configuration policy, not proof
of a runtime ancestor cpu.max limit. A Pod ancestor limit must be checked
on the actual node; do not assume that every cluster has one. Unlimited
container CPU configuration does not imply unlimited ancestors either.

## Low value or outside scope

- Sustained obvious throttling already diagnosed by counters: aggregate
  monitoring and configuration inspection often suffice.
- Offline batch work where throughput is the only concern: per-wait
  ancestry correlation may add little actionable information.
- No effective CPU quota: this feature has no quota constraint to find.
- CPU contention from weights, cpusets, affinity or topology; lock/I/O
  waits; C-state exit; IRQ delays: these need different measurements.
- RT/deadline scheduling and unrelated sched_ext policies: the current
  probes address fair-scheduler bandwidth and cannot generalize to them.
- A user restricted to a container namespace without host visibility or
  tracing privileges: the current collector is unsuitable. A future host
  agent would need its own overhead and access model.

## Why the present experiment is not enough

One pinned busy-loop task makes quota delays dominant and predictable.
It does not show whether the extra correlation changes diagnosis of a
sporadic application tail event. The current report also handles only
completed R-state switch-out waits: many server delays begin with a
wakeup and are outside its implemented scope.

An individual wait's throttle overlap cannot automatically be added to a
request's latency: requests can involve multiple threads, parallel work
and other waits. It also cannot be read as the counterfactual latency
saving after a quota change. Application correlation and controlled
interventions are needed for those claims.

## Evidence needed to reconsider the archived direction

The following is a possible reopening test, not committed follow-up work.

Use a request/response service and a CPU-consuming sibling under one
private parent quota. Keep the service's own quota unlimited. Start with
fixed CPUs to make interpretation tractable, then validate migration.
Measure application latency and the relevant service-thread waits during:

1. No parent quota, with sibling load unchanged.
2. Parent quota enabled, with the same sibling load.
3. Parent quota enabled, with sibling load removed or reduced.

Record cpu.stat and cpu.stat.local at both levels, ancestry/configuration,
task waits and constraint transitions. First attempt diagnosis using only
existing counters and perf/BCC output; then assess what the correlated
timeline actually adds. Support wakeup-origin waits before claiming this
experiment's report can diagnose that service.

Proceed only if the correlation answers a concrete question left open by
the existing methods, agrees with known constraints and changes a useful
diagnostic decision. Establish acceptable overhead and correctness before
production work. If counters alone provide the needed answer, or the
timeline adds no useful distinction, retain this as a documented recipe
and pursue another perf opportunity.

## Sources checked

- [Kernel cgroup v2 documentation](../../../../../Documentation/admin-guide/cgroup-v2.rst):
  cpu.stat, cpu.stat.local and cpu.max. Corresponding accounting is in
  kernel/sched/core.c and kernel/sched/fair.c in this baseline.
- [CFS bandwidth documentation](../../../../../Documentation/scheduler/sched-bwc.rst):
  hierarchical quota constraints.
- [Kubernetes resource documentation](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/):
  CPU limit enforcement, requests and optional Pod-level resources.
- [systemd resource control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html):
  CPUQuota and hierarchical unit resource control.
- [cAdvisor Prometheus metrics](https://github.com/google/cadvisor/blob/master/docs/storage/prometheus.md):
  container_cpu_cfs_* counters.
- BCC [runqlat](https://github.com/iovisor/bcc/blob/master/tools/runqlat.py)
  and [cpudist](https://github.com/iovisor/bcc/blob/master/tools/cpudist.py).

External sources were inspected on 2026-10-27; their main/latest URLs may
change. No production prevalence, incident rate or application benefit
has been measured by this assessment.
