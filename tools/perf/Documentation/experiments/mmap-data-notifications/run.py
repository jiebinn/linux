# SPDX-License-Identifier: GPL-2.0
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys

parser=argparse.ArgumentParser()
parser.add_argument('--cpus',required=True,help='four workload CPUs, comma separated')
parser.add_argument('--cpu-count',type=int,default=os.cpu_count(),help='dense online CPU count; use 0 for per-thread events')
parser.add_argument('--rounds',type=int,default=3)
parser.add_argument('--output',type=Path,default=Path('repeat.json'))
args=parser.parse_args()
cpus=[int(cpu) for cpu in args.cpus.split(',')]
if len(cpus)!=4 or len(set(cpus))!=4 or any(cpu not in os.sched_getaffinity(0) for cpu in cpus):
    parser.error('select four distinct CPUs available to the runner')
if args.cpu_count is None or not 0<=args.cpu_count<=1024 or (args.cpu_count and max(cpus)>=args.cpu_count):
    parser.error('use 0 for per-thread events or 1..1024 dense online CPUs')
if not 1<=args.rounds<=10:parser.error('--rounds must be 1..10')
if args.output.exists():parser.error('--output must not exist; preserve previous results')
root=Path(__file__).resolve().parent
result=[]
order=[]
for pair in range(args.rounds):
    order.extend((1,0) if pair%2==0 else (0,1))
for iteration,flag in enumerate(order):
    workload=subprocess.Popen([sys.executable,str(root/'process_control.py'),args.cpus],
                              stdout=subprocess.PIPE,text=True,start_new_session=True)
    sampler=None
    try:
        ready=workload.stdout.readline()
        match=re.fullmatch(r'READY (\d+) ([\d,]+)\n',ready)
        if not match:raise RuntimeError('Missing workload readiness')
        sampler=subprocess.Popen(['sudo','-n',str(root/'sampler'),str(flag),match[1],match[2],str(args.cpu_count)],
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        capture,errors=sampler.communicate(timeout=30)
        if sampler.returncode:raise RuntimeError(errors or 'Sampler failed')
        output=workload.communicate(timeout=5)[0]
        if workload.returncode:raise RuntimeError('Workload failed')
        if not re.search(r'lost=0 mmap_records=0\b',capture):
            raise RuntimeError('Capture lost samples or generated unexpected MMAP records')
        entry={'mmap':flag,'iteration':iteration,
               'ops':sum(map(int,re.findall(r'ops=(\d+)',output))),
               'cpu_ms':sum(map(int,re.findall(r'cpu_ns=(\d+)',output)))/1e6,
               'sampler':capture.strip(),'workload_exit':workload.returncode,'sampler_exit':sampler.returncode}
        result.append(entry)
        print(json.dumps(entry),flush=True)
    finally:
        if sampler is not None and sampler.poll() is None:
            sampler.terminate();sampler.wait(timeout=5)
        if workload.poll() is None:
            os.killpg(workload.pid,signal.SIGTERM);workload.wait(timeout=5)
args.output.write_text(json.dumps(result,indent=2)+'\n')
