#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check loss reads against LOST records; returns 1 on the known kernel bug."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpu", type=int, required=True)
    args = parser.parse_args()
    source = Path(__file__).with_name("lost_group.c")
    results = []
    with tempfile.TemporaryDirectory(prefix="perf-group-lost-") as tmp:
        binary = str(Path(tmp) / "lost_group")
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", binary], check=True)
        for group, inherit in ((1, 1), (0, 1), (1, 0), (1, 0), (0, 1),
                               (1, 1), (1, 1), (0, 1), (1, 0)):
            proc = subprocess.run(
                ["sudo", "-n", "timeout", "5", binary, str(group),
                 str(args.cpu), str(inherit)], check=True,
                capture_output=True, text=True, timeout=10)
            row = json.loads(proc.stdout)
            row["inherit"] = inherit
            row["passed"] = (row["record_lost"] > 0 and
                             row["read_lost_child_alive"] == row["record_lost"]
                             and row["read_lost_child_exited"] == row["record_lost"])
            results.append(row)
    print(json.dumps(results, indent=2))
    return int(not all(row["passed"] for row in results))


if __name__ == "__main__":
    raise SystemExit(main())
