// SPDX-License-Identifier: GPL-2.0
#include "builtin.h"
#include "builtin-sched-waits.h"
#include "perf.h"
#include "perf-sys.h"

#include "util/cpumap.h"
#include "util/evlist.h"
#include "util/evsel.h"
#include "util/evsel_fprintf.h"
#include "util/mutex.h"
#include "util/symbol.h"
#include "util/thread.h"
#include "util/header.h"
#include "util/session.h"
#include "util/tool.h"
#include "util/cloexec.h"
#include "util/thread_map.h"
#include "util/color.h"
#include "util/stat.h"
#include "util/string2.h"
#include "util/callchain.h"
#include "util/time-utils.h"

#include <subcmd/pager.h>
#include <subcmd/parse-options.h>
#include "util/trace-event.h"

#include "util/debug.h"
#include "util/event.h"
#include "util/util.h"
#include "util/synthetic-events.h"
#include "util/target.h"

#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/zalloc.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <inttypes.h>

#include <errno.h>
#include <semaphore.h>
#include <pthread.h>
#include <math.h>
#include <api/fs/fs.h>
#include <perf/cpumap.h>
#include <linux/time64.h>
#include <linux/err.h>

#include <linux/ctype.h>

#define MAX_CPUS 4096
#define COMM_LEN 20

#define TOP_WAIT_LIMIT 1000
#define TOP_WAIT_RUNS 16

enum top_wait_kind {
	TOP_WAIT_WAKEUP,
	TOP_WAIT_PREEMPT,
};

struct top_wait {
	u64 start;
	u64 ready;
	u64 end;
	u64 switched_out_after_waking;
	u64 last_cpu_since;
	u32 tid;
	u32 waker_tid;
	int waker_cpu;
	int old_cpu;
	int ready_cpu;
	int run_cpu;
	int last_cpu;
	u32 migrations;
	enum top_wait_kind kind;
	bool has_waking;
	bool has_ready;
	bool has_switched_out_after_waking;
	bool prior_out_seen;
	bool new_task;
	bool phase_order_gap;
	bool placement_gap;
	bool cpu_history_gap;
	char comm[COMM_LEN];
};

struct top_wait_state {
	struct top_wait wait;
	bool active;
	bool last_out_seen;
};

struct top_wait_run {
	u64 start;
	u64 end;
	u32 tid;
	int cpu;
	char comm[COMM_LEN];
};

struct top_wait_observation {
	struct top_wait_run runs[TOP_WAIT_RUNS];
	u64 covered_ns;
	u64 self_overlap_ns;
	u64 active_since;
	unsigned int nr_runs;
	unsigned int omitted_runs;
	int active_cpu;
};

struct top_cpu_run;

struct sched_waits {
	struct perf_tool tool;
	const char *input_name;
	const char *time_str;
	const char *cpu_list;
	bool force;
	DECLARE_BITMAP(cpu_bitmap, MAX_NR_CPUS);
	unsigned long nr_lost_events;
	const char	*top_wait_comm;
	unsigned int	top_waits_nr;
	unsigned int	top_waits_count;
	struct top_wait *top_waits;
	struct top_wait_observation *top_wait_observations;
	struct top_cpu_run *top_wait_cpu_runs;
	u64		top_wait_overlap_first;
	u64		top_wait_overlap_last;
	u64		*top_wait_first_switch;
	u64		top_wait_open;
	u64		top_wait_open_waking;
	u64		top_wait_open_ready;
	u64		top_wait_open_preempt;
	u64		top_wait_overwritten;
	u64		top_wait_missing_waking;
	u64		top_wait_missing_wakeup;
	u64		top_wait_history_gap;
	u64		top_wait_phase_order_gap;
	u64		top_wait_wakeup_running_discarded;
	u64		top_wait_preempt_stale_discarded;
	u64		top_wait_restarted;
	u64		top_wait_window_crossing;
	u64		top_wait_window_outside;
	struct perf_time_interval ptime;
};

static int process_lost(const struct perf_tool *tool __maybe_unused,
			union perf_event *event,
			struct perf_sample *sample,
			struct machine *machine __maybe_unused)
{
	char tstr[64];

	timestamp__scnprintf_usec(sample->time, tstr, sizeof(tstr));
	printf("%15s ", tstr);
	printf("lost %" PRI_lu64 " events on cpu %d\n", event->lost.lost, sample->cpu);

	return 0;
}


static struct top_wait_state *top_wait_get_state(struct machine *machine, u32 tid,
						struct thread **threadp)
{
	struct top_wait_state *state;
	struct thread *thread;

	thread = machine__findnew_thread(machine, -1, tid);
	if (!thread)
		return NULL;
	state = thread__priv(thread);
	if (!state) {
		state = zalloc(sizeof(*state));
		if (state)
			thread__set_priv(thread, state);
	}
	if (!state) {
		thread__put(thread);
		return NULL;
	}
	*threadp = thread;
	return state;
}

static void top_wait_start(struct sched_waits *sched, struct top_wait_state *state,
			   u64 time, u32 tid, const char *comm,
			   enum top_wait_kind kind)
{
	if (state->active) {
		if (state->wait.kind == TOP_WAIT_PREEMPT)
			sched->top_wait_open_preempt--;
		else if (state->wait.has_ready)
			sched->top_wait_open_ready--;
		else
			sched->top_wait_open_waking--;
	} else {
		sched->top_wait_open++;
	}
	if (kind == TOP_WAIT_PREEMPT)
		sched->top_wait_open_preempt++;
	else
		sched->top_wait_open_waking++;

	memset(&state->wait, 0, sizeof(state->wait));
	state->active = true;
	state->wait.start = time;
	state->wait.tid = tid;
	state->wait.kind = kind;
	state->wait.old_cpu = -1;
	state->wait.waker_cpu = -1;
	state->wait.ready_cpu = -1;
	state->wait.last_cpu = -1;
	state->wait.run_cpu = -1;
	strlcpy(state->wait.comm, comm ?: "?", sizeof(state->wait.comm));
}

static void top_wait_discard(struct sched_waits *sched, struct top_wait_state *state)
{
	if (!state->active)
		return;
	if (state->wait.kind == TOP_WAIT_PREEMPT)
		sched->top_wait_open_preempt--;
	else if (state->wait.has_ready)
		sched->top_wait_open_ready--;
	else
		sched->top_wait_open_waking--;
	sched->top_wait_open--;
	state->active = false;
}

static void top_wait_mark_ready(struct sched_waits *sched,
				struct top_wait_state *state, u64 time, int cpu)
{
	if (time < state->wait.start)
		state->wait.phase_order_gap = true;
	if (state->wait.kind == TOP_WAIT_WAKEUP && !state->wait.has_ready) {
		sched->top_wait_open_waking--;
		sched->top_wait_open_ready++;
	}
	state->wait.ready = time;
	state->wait.last_cpu_since = time;
	state->wait.has_ready = true;
	state->wait.ready_cpu = cpu;
	state->wait.last_cpu = cpu;
}

static void top_wait_keep(struct sched_waits *sched, const struct top_wait *wait)
{
	u64 duration = wait->end - wait->start;
	unsigned int i, child;
	struct top_wait *heap = sched->top_waits;

	if (sched->top_waits_count < sched->top_waits_nr) {
		i = sched->top_waits_count++;
		while (i &&
		       heap[(i - 1) / 2].end - heap[(i - 1) / 2].start > duration) {
			heap[i] = heap[(i - 1) / 2];
			i = (i - 1) / 2;
		}
		heap[i] = *wait;
		return;
	}
	if (duration <= heap[0].end - heap[0].start)
		return;
	i = 0;
	while ((child = i * 2 + 1) < sched->top_waits_count) {
		if (child + 1 < sched->top_waits_count &&
		    heap[child + 1].end - heap[child + 1].start <
		    heap[child].end - heap[child].start)
			child++;
		if (heap[child].end - heap[child].start >= duration)
			break;
		heap[i] = heap[child];
		i = child;
	}
	heap[i] = *wait;
}

static void top_wait_finish(struct sched_waits *sched, struct thread *thread,
			    struct top_wait_state *state, u64 time, int cpu)
{
	struct top_wait *wait = &state->wait;

	if (!state->active)
		return;
	state->active = false;
	sched->top_wait_open--;
	if (wait->kind == TOP_WAIT_PREEMPT)
		sched->top_wait_open_preempt--;
	else if (wait->has_ready)
		sched->top_wait_open_ready--;
	else
		sched->top_wait_open_waking--;
	if (time < wait->start)
		return;
	wait->end = time;
	wait->run_cpu = cpu;
	wait->prior_out_seen = state->last_out_seen;
	if (wait->has_ready && wait->ready > time)
		wait->phase_order_gap = true;
	if (wait->phase_order_gap)
		sched->top_wait_phase_order_gap++;
	if (wait->kind == TOP_WAIT_WAKEUP) {
		if (!wait->has_waking && !wait->new_task)
			sched->top_wait_missing_waking++;
		if (!wait->has_ready)
			sched->top_wait_missing_wakeup++;
	}
	if (wait->has_ready && wait->last_cpu != cpu)
		wait->placement_gap = true;
	if (wait->ready_cpu >= 0 && wait->ready_cpu < MAX_CPUS &&
	    (!sched->top_wait_first_switch[wait->ready_cpu] ||
	     sched->top_wait_first_switch[wait->ready_cpu] > wait->ready))
		wait->cpu_history_gap = true;
	if (wait->has_waking && wait->old_cpu >= 0 &&
	    wait->old_cpu < MAX_CPUS &&
	    (!sched->top_wait_first_switch[wait->old_cpu] ||
	     sched->top_wait_first_switch[wait->old_cpu] > wait->start))
		wait->cpu_history_gap = true;
	if (!sched->top_wait_first_switch[cpu] ||
	    sched->top_wait_first_switch[cpu] >
		(wait->has_ready ? wait->last_cpu_since : wait->start))
		wait->cpu_history_gap = true;
	if (wait->cpu_history_gap)
		sched->top_wait_history_gap++;

	if ((sched->ptime.start && wait->start < sched->ptime.start) ||
	    (sched->ptime.end && wait->end > sched->ptime.end)) {
		if ((!sched->ptime.start || wait->end > sched->ptime.start) &&
		    (!sched->ptime.end || wait->start < sched->ptime.end))
			sched->top_wait_window_crossing++;
		else
			sched->top_wait_window_outside++;
		return;
	}
	if ((sched->cpu_list && (cpu >= MAX_NR_CPUS || !test_bit(cpu, sched->cpu_bitmap))) ||
	    (symbol_conf.tid_list &&
	     !intlist__has_entry(symbol_conf.tid_list, wait->tid)) ||
	    (sched->top_wait_comm && strcmp(sched->top_wait_comm, wait->comm)))
		return;

	if (!thread__is_filtered(thread))
		top_wait_keep(sched, wait);
}

static int top_wait_sample(const struct perf_tool *tool, union perf_event *event __maybe_unused,
			   struct perf_sample *sample, struct machine *machine)
{
	struct sched_waits *sched = container_of(tool, struct sched_waits, tool);
	struct top_wait_state *state;
	struct thread *thread;
	const char *name = evsel__name(sample->evsel);
	u32 tid;
	int cpu = sample->cpu;

	if (cpu < 0 || cpu >= MAX_CPUS)
		return 0;
	if (!strcmp(name, "sched:sched_switch")) {
		u32 next = perf_sample__intval(sample, "next_pid");
		u32 prev = perf_sample__intval(sample, "prev_pid");
		const char state_char = perf_sample__taskstate(sample, "prev_state");

		if (!sched->top_wait_first_switch[cpu])
			sched->top_wait_first_switch[cpu] = sample->time;
		if (next) {
			state = top_wait_get_state(machine, next, &thread);
			if (!state)
				return -ENOMEM;
			top_wait_finish(sched, thread, state, sample->time, cpu);
			state->last_out_seen = false;
			thread__put(thread);
		}
		if (prev) {
			state = top_wait_get_state(machine, prev, &thread);
			if (!state)
				return -ENOMEM;
			if (state->active && state->wait.has_ready) {
				/* The task was still executing after a presumed wait. */
				if (state->wait.kind == TOP_WAIT_WAKEUP)
					sched->top_wait_wakeup_running_discarded++;
				else
					sched->top_wait_preempt_stale_discarded++;
				top_wait_discard(sched, state);
			}
			state->last_out_seen = true;
			if (state_char == 'R') {
				if (state->active)
					sched->top_wait_overwritten++;
				top_wait_start(sched, state, sample->time, prev,
					       perf_sample__strval(sample, "prev_comm"),
					       TOP_WAIT_PREEMPT);
				top_wait_mark_ready(sched, state, sample->time, cpu);
			} else if (state->active &&
				   state->wait.kind == TOP_WAIT_WAKEUP &&
				   state->wait.has_waking && !state->wait.has_ready) {
				state->wait.has_switched_out_after_waking = true;
				state->wait.switched_out_after_waking = sample->time;
			}
			thread__put(thread);
		}
		return 0;
	}
	if (!strcmp(name, "sched:sched_waking") ||
	    !strcmp(name, "sched:sched_wakeup") ||
	    !strcmp(name, "sched:sched_wakeup_new")) {
		bool waking = !strcmp(name, "sched:sched_waking");
		int target = perf_sample__intval(sample, "target_cpu");

		tid = perf_sample__intval(sample, "pid");
		/* A task waking itself is already on the CPU, so it did not wait. */
		if (sample->tid == tid)
			return 0;
		state = top_wait_get_state(machine, tid, &thread);
		if (!state)
			return -ENOMEM;
		if (waking) {
			if (!state->active || state->wait.kind == TOP_WAIT_WAKEUP) {
				if (state->active)
					sched->top_wait_restarted++;
				top_wait_start(sched, state, sample->time, tid,
				       perf_sample__strval(sample, "comm"), TOP_WAIT_WAKEUP);
				state->wait.has_waking = true;
				state->wait.waker_tid = sample->tid;
				state->wait.waker_cpu = cpu;
				state->wait.old_cpu = target;
			}
		} else if (!state->active || state->wait.kind != TOP_WAIT_WAKEUP) {
			top_wait_start(sched, state, sample->time, tid,
				       perf_sample__strval(sample, "comm"), TOP_WAIT_WAKEUP);
			state->wait.new_task = !strcmp(name, "sched:sched_wakeup_new");
			top_wait_mark_ready(sched, state, sample->time, target);
		} else if (!state->wait.has_ready) {
			top_wait_mark_ready(sched, state, sample->time, target);
		}
		thread__put(thread);
		return 0;
	}
	if (strcmp(name, "sched:sched_migrate_task"))
		return 0;
	tid = perf_sample__intval(sample, "pid");
	state = top_wait_get_state(machine, tid, &thread);
	if (!state)
		return -ENOMEM;
	if (state->active && state->wait.has_ready) {
		int old_cpu = perf_sample__intval(sample, "orig_cpu");
		int new_cpu = perf_sample__intval(sample, "dest_cpu");

		if (state->wait.last_cpu != old_cpu)
			state->wait.placement_gap = true;
		state->wait.last_cpu = new_cpu;
		state->wait.last_cpu_since = sample->time;
		state->wait.migrations++;
	}
	thread__put(thread);
	return 0;
}

static int top_wait_compare(const void *left, const void *right)
{
	const struct top_wait *a = left, *b = right;
	u64 da = a->end - a->start, db = b->end - b->start;

	return da < db ? 1 : da > db ? -1 : 0;
}

struct top_cpu_run {
	u64 since;
	u32 tid;
	char comm[COMM_LEN];
};

static void top_wait_add_run(struct top_wait_observation *obs, int cpu,
			     u64 start, u64 end, u32 tid, u32 victim_tid,
			     const char *comm)
{
	struct top_wait_run *run;

	if (end <= start)
		return;
	obs->covered_ns += end - start;
	if (tid == victim_tid)
		obs->self_overlap_ns += end - start;
	if (obs->nr_runs) {
		run = &obs->runs[obs->nr_runs - 1];
		if (run->tid == tid && run->cpu == cpu && run->end == start) {
			run->end = end;
			return;
		}
	}
	if (obs->nr_runs == TOP_WAIT_RUNS) {
		obs->omitted_runs++;
		return;
	}
	run = &obs->runs[obs->nr_runs++];
	run->start = start;
	run->end = end;
	run->tid = tid;
	run->cpu = cpu;
	strlcpy(run->comm, comm, sizeof(run->comm));
}

static void top_wait_cpu_until(struct sched_waits *sched, struct top_cpu_run *cpu_runs,
			       int cpu, u64 time)
{
	struct top_cpu_run *run = &cpu_runs[cpu];
	unsigned int i;

	if (!run->since || time <= run->since)
		return;
	if (time <= sched->top_wait_overlap_first ||
	    run->since >= sched->top_wait_overlap_last) {
		run->since = time;
		return;
	}
	for (i = 0; i < sched->top_waits_count; i++) {
		struct top_wait *wait = &sched->top_waits[i];
		struct top_wait_observation *obs = &sched->top_wait_observations[i];
		u64 start, end;

		if (obs->active_cpu != cpu)
			continue;
		start = max(run->since, obs->active_since);
		end = min(time, wait->end);
		if (end > start)
			top_wait_add_run(obs, cpu, start, end, run->tid,
					 wait->tid, run->comm);
	}
	run->since = time;
}

static int top_wait_overlap_sample(const struct perf_tool *tool,
				   union perf_event *event __maybe_unused,
				   struct perf_sample *sample,
				   struct machine *machine __maybe_unused)
{
	struct sched_waits *sched = container_of(tool, struct sched_waits, tool);
	struct top_cpu_run *cpu_runs = sched->top_wait_cpu_runs;
	const char *name = evsel__name(sample->evsel);
	int cpu = sample->cpu;
	unsigned int i;

	if (!strcmp(name, "sched:sched_switch")) {
		struct top_cpu_run *run;

		if (cpu < 0 || cpu >= MAX_CPUS)
			return 0;
		run = &cpu_runs[cpu];
		top_wait_cpu_until(sched, cpu_runs, cpu, sample->time);
		run->since = sample->time;
		run->tid = perf_sample__intval(sample, "next_pid");
		strlcpy(run->comm, perf_sample__strval(sample, "next_comm") ?: "?",
			sizeof(run->comm));
		return 0;
	}
	if (strcmp(name, "sched:sched_migrate_task"))
		return 0;
	for (i = 0; i < sched->top_waits_count; i++) {
		struct top_wait *wait = &sched->top_waits[i];
		struct top_wait_observation *obs = &sched->top_wait_observations[i];
		int old_cpu, new_cpu;

		if (wait->tid != perf_sample__intval(sample, "pid") ||
		    sample->time <= obs->active_since || sample->time >= wait->end)
			continue;
		old_cpu = perf_sample__intval(sample, "orig_cpu");
		new_cpu = perf_sample__intval(sample, "dest_cpu");
		if (obs->active_cpu == old_cpu && old_cpu >= 0 && old_cpu < MAX_CPUS)
			top_wait_cpu_until(sched, cpu_runs, old_cpu, sample->time);
		if (new_cpu >= 0 && new_cpu < MAX_CPUS) {
			obs->active_cpu = new_cpu;
			if (!sched->top_wait_first_switch[new_cpu] ||
			    sched->top_wait_first_switch[new_cpu] > sample->time) {
				if (!wait->cpu_history_gap)
					sched->top_wait_history_gap++;
				wait->cpu_history_gap = true;
			}
		} else {
			obs->active_cpu = -1;
		}
		obs->active_since = sample->time;
	}
	return 0;
}

static int top_wait_collect_overlap(struct sched_waits *sched)
{
	struct perf_data data = { .path = sched->input_name, .mode = PERF_DATA_MODE_READ,
				  .force = sched->force };
	struct perf_session *session;
	struct top_cpu_run *cpu_runs;
	unsigned int i;
	bool needed = false;
	int err;

	for (i = 0; i < sched->top_waits_count; i++) {
		if (sched->top_waits[i].has_ready &&
		    !sched->top_waits[i].phase_order_gap &&
		    !sched->top_waits[i].placement_gap) {
			needed = true;
			break;
		}
	}
	if (!needed)
		return 0;

	sched->top_wait_observations = calloc(sched->top_waits_count,
					      sizeof(*sched->top_wait_observations));
	cpu_runs = calloc(MAX_CPUS, sizeof(*cpu_runs));
	if (!sched->top_wait_observations || !cpu_runs) {
		err = -ENOMEM;
		goto out_free;
	}
	for (i = 0; i < sched->top_waits_count; i++) {
		const struct top_wait *wait = &sched->top_waits[i];
		struct top_wait_observation *obs = &sched->top_wait_observations[i];

		obs->active_cpu = wait->has_ready && !wait->phase_order_gap ?
				  wait->ready_cpu : -1;
		obs->active_since = wait->ready;
		if (wait->has_ready && !wait->phase_order_gap &&
		    !wait->placement_gap) {
			if (!sched->top_wait_overlap_first ||
			    wait->ready < sched->top_wait_overlap_first)
				sched->top_wait_overlap_first = wait->ready;
			if (wait->end > sched->top_wait_overlap_last)
				sched->top_wait_overlap_last = wait->end;
		}
	}
	/* This second pass only retains CPU runs for the selected intervals. */
	sched->top_wait_cpu_runs = cpu_runs;
	sched->tool.sample = top_wait_overlap_sample;
	session = perf_session__new(&data, &sched->tool);
	if (IS_ERR(session)) {
		err = PTR_ERR(session);
		goto out_free;
	}
	err = perf_session__process_events(session);
	perf_session__delete(session);
out_free:
	sched->top_wait_cpu_runs = NULL;
	free(cpu_runs);
	return err;
}

static void top_wait_print(struct sched_waits *sched)
{
	unsigned int i;

	printf("Longest %u complete waits (CPU filter selects run CPU):\n",
	       sched->top_waits_count);
	for (i = 0; i < sched->top_waits_count; i++) {
		const struct top_wait *w = &sched->top_waits[i];

		printf("%3u %10.3f us  %s/%u  %s  cpu %d",
		       i + 1, (double)(w->end - w->start) / NSEC_PER_USEC,
		       w->comm, w->tid,
		       w->kind == TOP_WAIT_PREEMPT ? "preempt" :
		       w->new_task ? "new-task" :
		       w->has_waking ? "wakeup" : "queued-only",
		       w->run_cpu);
		if (w->kind == TOP_WAIT_WAKEUP) {
			if (w->has_waking) {
				if (w->waker_tid)
					printf("  waker=%u@CPU%d", w->waker_tid,
					       w->waker_cpu);
				else
					printf("  waker=idle/IRQ@CPU%d", w->waker_cpu);
				printf(" old_cpu=%d", w->old_cpu);
			}
			if (w->has_ready && !w->phase_order_gap) {
				if (w->has_waking)
					printf("  waking=%" PRIu64 " activation=%.3f us",
					       w->start,
					       (double)(w->ready - w->start) / NSEC_PER_USEC);
				printf("  ready=%" PRIu64 " queued=%.3f us selected_cpu=%d",
				       w->ready,
				       (double)(w->end - w->ready) / NSEC_PER_USEC,
				       w->ready_cpu);
			} else if (!w->has_ready) {
				printf("  ready=unknown (queue time and placement unknown)");
			}
			if (w->has_switched_out_after_waking)
				printf("  switched_out=+%.3f us",
				       (double)(w->switched_out_after_waking -
						w->start) / NSEC_PER_USEC);
		}
		printf("  start=%" PRIu64 " end=%" PRIu64 " migrations=%u",
		       w->start, w->end, w->migrations);
		if (w->kind == TOP_WAIT_WAKEUP && !w->has_waking && !w->new_task)
			printf("  [waking missing]");
		if (w->new_task)
			printf("  [new task]");
		if (w->kind == TOP_WAIT_WAKEUP && !w->new_task &&
		    !w->prior_out_seen)
			printf("  [prior switch-out unobserved]");
		if (w->cpu_history_gap)
			printf("  [CPU history incomplete]");
		if (w->placement_gap)
			printf("  [placement incomplete]");
		if (w->phase_order_gap)
			printf("  [phase timestamp order invalid]");
		if (sched->top_wait_observations &&
		    sched->top_wait_observations[i].self_overlap_ns)
			printf("  [invalid: task ran during queued wait]");
		printf("\n");
		if (sched->top_wait_observations && w->has_ready &&
		    !w->phase_order_gap &&
		    !w->placement_gap) {
			const struct top_wait_observation *obs = &sched->top_wait_observations[i];
			unsigned int j;

			printf("      observed target CPU time: %.3f us (overlap, not cause)\n",
			       (double)obs->covered_ns / NSEC_PER_USEC);
			for (j = 0; j < obs->nr_runs; j++) {
				const struct top_wait_run *run = &obs->runs[j];

				printf("        +%10.3f us CPU%-4d %-20s/%-7u ran %.3f us\n",
				       (double)(run->start - w->ready) / NSEC_PER_USEC,
				       run->cpu, run->comm, run->tid,
				       (double)(run->end - run->start) / NSEC_PER_USEC);
			}
			if (obs->omitted_runs)
				printf("        ... %u later runs omitted\n", obs->omitted_runs);
		}
	}
	printf("Trace-wide diagnostics: open waits at trace end: %" PRIu64
	       " (waking only=%" PRIu64 ", ready but not running=%" PRIu64
	       ", preempted=%" PRIu64 "); repeated waking restarts: %" PRIu64
	       "; ready wakeups discarded at switch-out: %" PRIu64
	       "; stale preemptions discarded at switch-out: %" PRIu64
	       "; overwritten starts: %" PRIu64
	       "; completed without waking: %" PRIu64 "; without wakeup: %" PRIu64
	       "; with incomplete CPU history: %" PRIu64
	       "; invalid phase order: %" PRIu64
	       "; crossing time window: %" PRIu64
	       "; outside time window: %" PRIu64 "\n",
	       sched->top_wait_open, sched->top_wait_open_waking,
	       sched->top_wait_open_ready, sched->top_wait_open_preempt,
	       sched->top_wait_restarted,
	       sched->top_wait_wakeup_running_discarded,
	       sched->top_wait_preempt_stale_discarded,
	       sched->top_wait_overwritten,
	       sched->top_wait_missing_waking, sched->top_wait_missing_wakeup,
	       sched->top_wait_history_gap, sched->top_wait_phase_order_gap,
	       sched->top_wait_window_crossing, sched->top_wait_window_outside);
	if (sched->nr_lost_events)
		printf("Trace has %lu lost events; interval completeness cannot be verified.\n",
		       sched->nr_lost_events);
}

static int sched_waits__report(struct sched_waits *sched)
{
	struct perf_data data = { .path = sched->input_name, .mode = PERF_DATA_MODE_READ,
				  .force = sched->force };
	struct perf_session *session;
	bool pipe_input = false;
	int err;

	if (!sched->top_waits_nr || sched->top_waits_nr > TOP_WAIT_LIMIT) {
		pr_err("--top must be between 1 and %u\n", TOP_WAIT_LIMIT);
		return -EINVAL;
	}
	sched->top_waits = calloc(sched->top_waits_nr, sizeof(*sched->top_waits));
	sched->top_wait_first_switch = calloc(MAX_CPUS, sizeof(u64));
	if (!sched->top_waits || !sched->top_wait_first_switch) {
		err = -ENOMEM;
		goto out_free;
	}
	sched->tool.sample = top_wait_sample;
	sched->tool.comm = perf_event__process_comm;
	sched->tool.fork = perf_event__process_fork;
	sched->tool.exit = perf_event__process_exit;
	sched->tool.lost = process_lost;
	sched->tool.ordering_requires_timestamps = true;
	session = perf_session__new(&data, &sched->tool);
	if (IS_ERR(session)) {
		err = PTR_ERR(session);
		goto out_free;
	}
	pipe_input = perf_data__is_pipe(session->data);
	err = symbol__init(perf_session__env(session));
	if (err)
		goto out_session;
	if (sched->cpu_list) {
		err = perf_session__cpu_bitmap(session, sched->cpu_list, sched->cpu_bitmap);
		if (err < 0)
			goto out_session;
	}
	if (perf_time__parse_str(&sched->ptime, sched->time_str)) {
		err = -EINVAL;
		goto out_session;
	}
	if (!evlist__find_tracepoint_by_name(session->evlist, "sched:sched_switch")) {
		pr_err("No sched_switch events found. Record sched:sched_switch with perf record.\n");
		err = -EINVAL;
		goto out_session;
	}
	err = perf_session__process_events(session);
	if (!err) {
		sched->nr_lost_events = evlist__stats(session->evlist)->total_lost;
		qsort(sched->top_waits, sched->top_waits_count,
		      sizeof(*sched->top_waits), top_wait_compare);
		perf_session__delete(session);
		session = NULL;
		if (sched->top_waits_count && !pipe_input)
			err = top_wait_collect_overlap(sched);
	}
	if (!err) {
		top_wait_print(sched);
		if (pipe_input)
			printf("CPU running context is unavailable for pipe input.\n");
	}
out_session:
	if (session)
		perf_session__delete(session);
out_free:
	free(sched->top_wait_observations);
	free(sched->top_wait_first_switch);
	free(sched->top_waits);
	return err;
}

int cmd_sched_waits(int argc, const char **argv)
{
	struct sched_waits sched = { .input_name = "perf.data", .top_waits_nr = 20 };
	const struct option options[] = {
		OPT_STRING('i', "input", &sched.input_name, "file", "input file name"),
		OPT_UINTEGER(0, "top", &sched.top_waits_nr,
			     "show N longest completed waits (max 1000)"),
		OPT_STRING(0, "comm", &sched.top_wait_comm, "name", "filter by exact task name"),
		OPT_STRING('t', "tid", &symbol_conf.tid_list_str,
			   "tid[,tid...]", "filter by thread ID"),
		OPT_STRING('C', "cpu", &sched.cpu_list, "cpu", "filter by run CPU"),
		OPT_STRING(0, "time", &sched.time_str, "start,stop",
			   "analyze complete intervals in time span"),
		OPT_BOOLEAN('f', "force", &sched.force, "read possibly damaged input file"),
		OPT_END()
	};
	const char * const usage[] = { "perf sched waits report [<options>]", NULL };

	if (argc < 1 || strcmp(argv[0], "report")) {
		pr_err("Expected 'perf sched waits report'\n");
		return -EINVAL;
	}
	argc = parse_options(argc, argv, options, usage, 0);
	if (argc)
		usage_with_options(usage, options);
	perf_tool__init(&sched.tool, /*ordered_events=*/true);
	sched.tool.attr = perf_event__process_attr;
	sched.tool.tracing_data = perf_event__process_tracing_data;
	sched.tool.build_id = perf_event__process_build_id;
	sched.tool.feature = perf_event__process_feature;
	thread__set_priv_destructor(free);
	return sched_waits__report(&sched);
}
