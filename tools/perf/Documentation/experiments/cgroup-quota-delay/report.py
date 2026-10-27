# SPDX-License-Identifier: GPL-2.0
import argparse
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument("directory", type=Path)
parser.add_argument("--throttle-events", type=Path)
parser.add_argument("--include-waits", action="store_true",
                    help="include each completed wait and observed constraint overlaps")
args = parser.parse_args()
root = args.directory
throttle_file = args.throttle_events or root.parent / "throttle-events.txt"
pattern = re.compile(r"^\[(\d+)\]\s+(\d+)\.(\d{9}):\s+sched:sched_switch:\s+(.+?):(\d+) \[\d+\] (\S+) ==> (.+):(\d+) \[\d+\]")


def intersection(a, b):
    return max(0, min(a[1], b[1]) - max(a[0], b[0]))


def union(intervals):
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


result = {}
for case in ("unlimited", "parent-limited", "leaf-limited"):
    first, last = [json.loads(line) for line in (root / f"{case}.jsonl").read_text().splitlines()]
    if len(first["affinity"]) != 1:
        raise ValueError("This prototype requires a single pinned CPU")
    cpu = first["affinity"][0]
    pid = first["pid"]
    lo, hi = first["time_ns"], last["time_ns"]
    if first["pid"] != last["pid"] or first["lineage"] != [
            {key: entry[key] for key in ("path", "id", "cpu_max")}
            for entry in last["lineage"]]:
        raise ValueError("Task identity or cgroup configuration changed")
    ids = {entry["id"] for entry in first["lineage"]}
    spans = {id: [] for id in ids}
    active = {}
    for line in throttle_file.read_text().splitlines():
        fields = line.split()
        if len(fields) != 5 or fields[0] not in ("T", "U"):
            continue
        event, stamp, event_cpu, rq, id = fields
        stamp, event_cpu, id = int(stamp), int(event_cpu), int(id)
        if id not in ids or event_cpu != cpu:
            continue
        key = (id, rq)
        if event == "T":
            if key in active:
                raise ValueError(f"Repeated throttle start: {key}")
            active[key] = stamp
        else:
            if key not in active:
                raise ValueError(f"Unpaired unthrottle: {key}")
            start = active.pop(key)
            if stamp < start:
                raise ValueError("Invalid throttle timestamp order")
            spans[id].append((start, stamp))
    if active:
        raise ValueError(f"Incomplete throttle intervals: {active}")
    waits = []
    start = None
    previous_stamp = None
    for line in (root / f"{case}-events.txt").read_text().splitlines():
        if "PERF_RECORD_LOST" in line or "LOST" in line:
            raise ValueError("Lost perf events")
        m = pattern.match(line)
        if not m:
            continue
        event_cpu, sec, ns, prev_comm, prev, state, next_comm, next_pid = m.groups()
        if int(event_cpu) != cpu:
            raise ValueError("Unexpected CPU; migration tracking is not implemented")
        stamp = int(sec) * 1_000_000_000 + int(ns)
        if previous_stamp is not None and stamp < previous_stamp:
            raise ValueError("Scheduler events must be timestamp ordered")
        previous_stamp = stamp
        if int(next_pid) == pid and start is not None:
            if lo <= start < stamp <= hi:
                waits.append((start, stamp))
            start = None
        if int(prev) == pid:
            start = stamp if state.startswith("R") else None
    total = sum(end - start for start, end in waits)
    merged = union([span for intervals in spans.values() for span in intervals])
    effective = sum(intersection(wait, span) for wait in waits for span in merged)
    by_group = []
    for entry in last["lineage"]:
        overlap = sum(intersection(wait, span) for wait in waits for span in spans[entry["id"]])
        by_group.append({**entry,
                         "observed_throttle_intervals": len(spans[entry["id"]]),
                         "wait_throttle_overlap_ms": overlap / 1e6})
    result[case] = {
        "pid": pid, "cpu": cpu, "wall_ms": last["wall_ns"] / 1e6,
        "task_cpu_ms": last["cpu_ns"] / 1e6,
        "completed_runnable_waits": len(waits),
        "max_wait_ms": max((end - start for start, end in waits), default=0) / 1e6,
        "total_runnable_wait_ms": total / 1e6,
        "effective_throttle_overlap_ms": effective / 1e6,
        "effective_throttle_overlap_percent": effective / total * 100 if total else 0,
        "lineage": by_group}
    if args.include_waits:
        result[case]["waits"] = []
        for wait in waits:
            overlap = sum(intersection(wait, span) for span in merged)
            result[case]["waits"].append({
                "start_ns": wait[0], "end_ns": wait[1],
                "duration_ns": wait[1] - wait[0],
                "effective_throttle_overlap_ns": overlap,
                "without_observed_throttle_ns": wait[1] - wait[0] - overlap,
                "constraints": [
                    {"path": entry["path"], "id": entry["id"], "overlap_ns": amount}
                    for entry in first["lineage"]
                    if (amount := sum(intersection(wait, span)
                                      for span in spans[entry["id"]]))]})
print(json.dumps(result, indent=2))
