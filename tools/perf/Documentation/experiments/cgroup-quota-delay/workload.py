# SPDX-License-Identifier: GPL-2.0
import ctypes
import json
import os
from pathlib import Path
import sys
import time

leaf = Path(sys.argv[1])
(leaf / "cgroup.procs").write_text(str(os.getpid()))
os.sched_setaffinity(0, {int(sys.argv[2])})
ctypes.CDLL(None).prctl(15, ctypes.c_char_p(b"quota-child"), 0, 0, 0)

def stats(group):
    return {key: int(value) for key, value in
            (line.split() for line in (group / "cpu.stat").read_text().splitlines())}

groups = [leaf, leaf.parent]
before = {str(group): stats(group) for group in groups}
lineage = [{"path": str(group.relative_to("/sys/fs/cgroup")),
            "id": group.stat().st_ino,
            "cpu_max": (group / "cpu.max").read_text().strip()}
           for group in groups]
start = time.monotonic_ns()
cpu_start = time.process_time_ns()
print(json.dumps({"phase": "start", "pid": os.getpid(),
                  "affinity": sorted(os.sched_getaffinity(0)), "time_ns": start,
                  "lineage": lineage}), flush=True)
count = 0
while time.monotonic_ns() - start < int(float(sys.argv[3]) * 1e9):
    for _ in range(10000):
        count += 1
end = time.monotonic_ns()
cpu_end = time.process_time_ns()
after = {str(group): stats(group) for group in groups}
print(json.dumps({"phase": "end", "pid": os.getpid(), "time_ns": end,
                  "wall_ns": end-start, "cpu_ns": cpu_end-cpu_start,
                  "lineage": [{**entry, "cpu_stat_delta":
                    {key: after[str(group)][key] - before[str(group)].get(key, 0)
                     for key in after[str(group)]}}
                    for entry, group in zip(lineage, groups)]}), flush=True)
