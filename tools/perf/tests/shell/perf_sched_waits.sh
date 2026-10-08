#!/bin/sh
# perf sched waits report with manually recorded wakeup phases
# SPDX-License-Identifier: GPL-2.0

set -e

if [ "$(id -u)" != 0 ]; then
	echo '[Skip] No root permission'
	exit 2
fi

if ! perf list sched:sched_waking 2>/dev/null | grep -q sched_waking; then
	echo '[Skip] sched_waking is unavailable'
	exit 2
fi

perfdata=$(mktemp /tmp/perf_sched_waits.data.XXXXXX)
output=$(mktemp /tmp/perf_sched_waits.out.XXXXXX)
trap 'rm -f "$perfdata" "$perfdata.old" "$output"' EXIT HUP INT TERM

perf record -a -R -m 1024 -c 1 -o "$perfdata" \
	-e sched:sched_switch -e sched:sched_waking \
	-e sched:sched_wakeup -e sched:sched_wakeup_new \
	-e sched:sched_migrate_task -e sched:sched_process_fork \
	-- perf bench sched pipe -l 1000 >/dev/null 2>&1
perf evlist -i "$perfdata" | grep -q '^sched:sched_waking$'
perf evlist -i "$perfdata" | grep -q '^sched:sched_wakeup$'
perf sched waits report -i "$perfdata" --top 5 >"$output"
grep -q '^Longest [1-5] complete waits' "$output"
grep -q '^Trace-wide diagnostics:' "$output"
if grep -q '\[invalid: task ran during queued wait\]' "$output"; then
	echo 'A wait includes the task running during its queued phase'
	exit 1
fi
