#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compare BPF lock workload filtering with a background contention control."""
import argparse
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent


def trial(perf, mode, cpus, binaries):
    noise = subprocess.Popen(
        [binaries["noise"], "2", "4194304", cpus], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True)
    collector = None
    try:
        if not select.select([noise.stdout], [], [], 5)[0]:
            raise RuntimeError("background workload readiness timeout")
        ready = noise.stdout.readline()
        if not ready.startswith("READY "):
            raise RuntimeError("unexpected background output: " + ready)
        pid = int(ready.split()[1])
        command = ["sudo", "-n", perf, "lock", "contention", "-b", "-t",
                   "-Y", "rwsem:W", "-L", "mmap_lock"]
        if mode == "system":
            command += ["-a"]
        elif mode == "pid":
            command += ["-p", str(pid)]
        command += ["--"]
        if mode == "target":
            command += [binaries["main_contender"], "3", "4194304", cpus, "now"]
        else:
            command += [binaries["quiet_wait"]]
        collector = subprocess.Popen(command, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        # Timing assumption: this is not a collector readiness API.
        # System/PID controls must observe contention before interpreting
        # an empty filtered result. Slow attachment can be inconclusive.
        time.sleep(1)
        if collector.poll() is not None:
            raise RuntimeError("collector exited before background release")
        os.kill(pid, signal.SIGUSR1)
        background, background_err = noise.communicate(timeout=8)
        stdout, stderr = collector.communicate(timeout=8)
        if noise.returncode or collector.returncode:
            raise RuntimeError(f"collection failed: {background_err}\n{stderr}")
        rows = [line.split() for line in (stdout + stderr).splitlines()
                if line.rstrip().endswith(("op-noise", "scope-target"))]
        background_rows = [row for row in rows if row[-1] == "op-noise"]
        match = re.search(r"^READY (\d+)", stdout, re.MULTILINE)
        target_pid = int(match[1]) if match else None
        target_rows = [row for row in rows
                       if row[-1] == "scope-target" and int(row[-2]) == target_pid]
        return {"mode": mode, "background_rows": background_rows,
                "target_pid": target_pid, "target_main_rows": target_rows,
                "stdout": stdout, "stderr": stderr,
                "background": ready + background + background_err}
    finally:
        for proc in (noise, collector):
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.communicate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--cpus", required=True)
    args = parser.parse_args()
    results = {}
    with tempfile.TemporaryDirectory(prefix="perf-lock-scope-") as tmp:
        binaries = {}
        for name in ("noise", "main_contender", "quiet_wait"):
            binary = str(Path(tmp) / name)
            subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-pthread", str(HERE / (name + ".c")),
                            "-o", binary], check=True)
            binaries[name] = binary
        for label, perf in (("baseline", args.baseline),
                            ("candidate", args.candidate)):
            results[label] = [trial(perf, mode, args.cpus, binaries)
                              for mode in ("quiet", "target", "system", "pid")]
    print(json.dumps(results, indent=2))
    for label in results:
        quiet, target, system, pid = results[label]
        if not system["background_rows"] or not pid["background_rows"]:
            raise RuntimeError("positive control empty: experiment inconclusive")
        if not target["target_main_rows"]:
            raise RuntimeError("target main TID not observed: inconclusive")
    if not results["baseline"][0]["background_rows"]:
        raise RuntimeError("baseline contamination not reproduced")
    if any(row["background_rows"] for row in results["candidate"][:2]):
        raise RuntimeError("candidate still collects unrelated tasks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
