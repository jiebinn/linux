# SPDX-License-Identifier: GPL-2.0
import argparse
import math
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument("--cpu", type=int, required=True)
parser.add_argument("--duration", type=float, default=2)
parser.add_argument("--output-dir", type=Path, default=Path("quota-capture"))
parser.add_argument("--perf", default="perf")
args = parser.parse_args()
if not math.isfinite(args.duration) or args.duration <= 0:
    parser.error("--duration must be finite and positive")
if args.cpu not in os.sched_getaffinity(0):
    parser.error("--cpu must be available in the runner's affinity")
if os.geteuid() != 0:
    parser.error("root is required for cgroup creation and recording")
args.output_dir.mkdir(parents=True, exist_ok=True)
if any(args.output_dir.iterdir()):
    parser.error("--output-dir must be empty to preserve previous captures")
perf = args.perf
cases = [("unlimited", "max 100000", "max 100000"),
         ("parent-limited", "20000 100000", "max 100000"),
         ("leaf-limited", "max 100000", "20000 100000")]
created = []
try:
    for name, parent_quota, leaf_quota in cases:
        parent = Path("/sys/fs/cgroup") / f"perf-quota-hierarchy-{os.getpid()}-{name}"
        parent.mkdir()
        created.append(parent)
        (parent / "cpu.max").write_text(parent_quota)
        (parent / "cgroup.subtree_control").write_text("+cpu")
        leaf = parent / "workload"
        leaf.mkdir()
        created.append(leaf)
        (leaf / "cpu.max").write_text(leaf_quota)
        with (args.output_dir / f"{name}.jsonl").open("w") as out, (args.output_dir / f"{name}-record.log").open("w") as err:
            subprocess.run([perf, "record", "-C", str(args.cpu), "-R", "-m", "128", "-c", "1",
                            "--clockid", "mono", "-e", "sched:sched_switch",
                            "-e", "sched:sched_waking", "-e", "sched:sched_wakeup",
                            "-o", str(args.output_dir / f"{name}.data"), "--",
                            "/usr/bin/python3", str(root / "workload.py"),
                            str(leaf), str(args.cpu), str(args.duration)],
                           stdout=out, stderr=err, check=True)
        print((args.output_dir / f"{name}.jsonl").read_text(), end="", flush=True)
        leaf.rmdir()
        created.remove(leaf)
        parent.rmdir()
        created.remove(parent)
finally:
    for group in reversed(created):
        group.rmdir()
