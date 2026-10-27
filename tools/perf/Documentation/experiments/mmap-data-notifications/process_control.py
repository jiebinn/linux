# SPDX-License-Identifier: GPL-2.0
import os
import signal
import subprocess
import sys
from pathlib import Path

children=[]
tids=[]
try:
    for cpu in map(int, sys.argv[1].split(",")):
        child=subprocess.Popen([str(Path(__file__).resolve().parent/'workload'),'1.5','4096',str(cpu)],stdout=subprocess.PIPE,text=True)
        children.append(child)
        fields=child.stdout.readline().split()
        if len(fields)!=3 or fields[0]!='READY':raise RuntimeError('Child not ready')
        tids.append(fields[2])
    def start(sig, frame):
        for child in children:os.kill(child.pid,signal.SIGUSR1)
    signal.signal(signal.SIGUSR1,start)
    print('READY',os.getpid(),','.join(tids),flush=True)
    for child in children:
        print(child.stdout.read(),end='',flush=True)
        if child.wait():raise RuntimeError('Child workload failed')
finally:
    for child in children:
        if child.poll() is None:
            child.terminate();child.wait()
