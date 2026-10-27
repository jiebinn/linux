// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
static volatile sig_atomic_t start_run;
static atomic_int ready;
static void *region;
static size_t region_size;
static double duration;
struct worker { int cpu, tid, failed; unsigned long ops; uint64_t syscall_ns, cpu_ns; };
static uint64_t now(clockid_t clock) { struct timespec t; clock_gettime(clock, &t); return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec; }
static void begin(int sig) { (void)sig; start_run = 1; }
static void *run(void *arg)
{
    struct worker *w = arg; cpu_set_t mask;
    CPU_ZERO(&mask); CPU_SET(w->cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask)) { perror("affinity"); exit(1); }
    prctl(PR_SET_NAME, "perf-rwsem", 0, 0, 0); w->tid = syscall(SYS_gettid);
    atomic_fetch_add(&ready, 1);
    while (!start_run) usleep(1000);
    uint64_t start = now(CLOCK_MONOTONIC), cstart = now(CLOCK_THREAD_CPUTIME_ID);
    while (now(CLOCK_MONOTONIC) - start < (uint64_t)(duration * 1e9)) {
        uint64_t entry = now(CLOCK_MONOTONIC);
        if (mprotect(region, region_size, w->ops & 1 ? PROT_READ : PROT_READ | PROT_WRITE)) { w->failed=errno; break; }
        w->syscall_ns += now(CLOCK_MONOTONIC) - entry; w->ops++;
    }
    w->cpu_ns = now(CLOCK_THREAD_CPUTIME_ID) - cstart; return NULL;
}
int main(int argc, char **argv)
{
    if (argc != 4) { fprintf(stderr, "usage: workload DURATION BYTES CPU,CPU,...\n"); return 1; }
    duration = strtod(argv[1], NULL); region_size = strtoull(argv[2], NULL, 10);
    if (!isfinite(duration) || duration <= 0 || duration > 10 || !region_size || region_size > 67108864) return 1;
    struct worker workers[32] = {}; pthread_t threads[32]; int n = 0;
    char *token = strtok(argv[3], ",");
    while (token && n < 32) { workers[n++].cpu = atoi(token); token = strtok(NULL, ","); }
    if (!n || token) return 1;
    for (int i=0; i<n; i++) if (workers[i].cpu<0 || workers[i].cpu>=CPU_SETSIZE) return 1;
    signal(SIGUSR1, begin); prctl(PR_SET_NAME, "rwsem-main", 0, 0, 0);
    region = mmap(NULL, region_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 1; } memset(region, 0, region_size);
    for (int i=0; i<n; i++) if (pthread_create(&threads[i], NULL, run, &workers[i])) return 1;
    while (atomic_load(&ready) != n) usleep(1000);
    printf("READY %d ", getpid());
    for (int i=0; i<n; i++) printf("%s%d", i ? "," : "", workers[i].tid);
    putchar('\n'); fflush(stdout);
    for (int i=0; i<n; i++) pthread_join(threads[i], NULL);
    printf("RESULT threads=%d bytes=%zu duration=%.3f\n", n, region_size, duration);
    int failed=0;
    for (int i=0; i<n; i++) { printf("THREAD cpu=%d tid=%d ops=%lu syscall_ns=%llu cpu_ns=%llu error=%d\n", workers[i].cpu, workers[i].tid, workers[i].ops, (unsigned long long)workers[i].syscall_ns, (unsigned long long)workers[i].cpu_ns, workers[i].failed); failed |= workers[i].failed; }
    munmap(region, region_size); return !!failed;
}
