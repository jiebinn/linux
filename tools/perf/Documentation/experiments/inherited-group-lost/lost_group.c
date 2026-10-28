// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *what)
{
	perror(what);
	exit(1);
}

static uint64_t now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		fail("clock");
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void busy(unsigned int ms)
{
	uint64_t end = now() + ms * 1000000ULL;

	while (now() < end)
		asm volatile("" ::: "memory");
}

static void copy_ring(const char *data, size_t capacity, uint64_t offset,
		      void *out, size_t size)
{
	size_t pos = offset % capacity;
	size_t first = size < capacity - pos ? size : capacity - pos;

	memcpy(out, data + pos, first);
	memcpy((char *)out + first, data, size - first);
}

static uint64_t lost_records(void *map, size_t page, unsigned int *samples)
{
	struct perf_event_mmap_page *meta = map;
	uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
	uint64_t tail = meta->data_tail, lost = 0;
	const char *data = (char *)map + page;

	if (head - tail > page)
		fail("ring overflow");
	while (tail < head) {
		struct perf_event_header header;

		copy_ring(data, page, tail, &header, sizeof(header));
		if (header.size < sizeof(header) || header.size > head - tail)
			fail("ring header");
		if (header.type == PERF_RECORD_SAMPLE)
			(*samples)++;
		if (header.type == PERF_RECORD_LOST) {
			uint64_t count;

			if (header.size < 24)
				fail("LOST record");
			copy_ring(data, page, tail + 16, &count, sizeof(count));
			lost += count;
		}
		tail += header.size;
	}
	__atomic_store_n(&meta->data_tail, head, __ATOMIC_RELEASE);
	return lost;
}

static uint64_t read_lost(int fd, int group)
{
	uint64_t values[8] = {};
	ssize_t size = read(fd, values, sizeof(values));

	if (group) {
		if (size != 40 || values[0] != 2)
			fail("group read");
		return values[2];
	}
	if (size != 16)
		fail("one read");
	return values[1];
}

int main(int argc, char **argv)
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.size = sizeof(attr),
		.config = PERF_COUNT_SW_TASK_CLOCK,
		.sample_period = 100000,
		.sample_type = PERF_SAMPLE_IP,
		.read_format = PERF_FORMAT_LOST,
		.exclude_kernel = 1,
		.exclude_hv = 1,
		.inherit = 1,
		.disabled = 1,
	};
	cpu_set_t mask;
	uint64_t live, exited, stream_lost;
	unsigned int samples = 0;
	int fd, member, ready[2], release[2], status;
	int group = argc > 1 ? atoi(argv[1]) : 1;
	int cpu = argc > 2 ? atoi(argv[2]) : sched_getcpu();
	size_t page = sysconf(_SC_PAGESIZE);
	void *map;
	char token;
	pid_t child;

	if (group != 0 && group != 1)
		return 1;
	if (cpu < 0 || cpu >= CPU_SETSIZE)
		return 1;
	CPU_ZERO(&mask);
	CPU_SET(cpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask))
		fail("affinity");
	if (argc > 3)
		attr.inherit = atoi(argv[3]);
	if (group)
		attr.read_format |= PERF_FORMAT_GROUP;
	fd = syscall(SYS_perf_event_open, &attr, 0, cpu, -1, 0);
	if (fd < 0)
		fail("perf_event_open leader");
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.sample_period = 0;
	attr.read_format = PERF_FORMAT_LOST;
	member = syscall(SYS_perf_event_open, &attr, 0, cpu, fd, 0);
	if (member < 0)
		fail("perf_event_open member");
	map = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		fail("perf ring");
	if (pipe(ready) || pipe(release))
		fail("pipe");
	if (ioctl(fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP))
		fail("enable");
	child = fork();
	if (child < 0)
		fail("fork");
	if (!child) {
		close(ready[0]);
		close(release[1]);
		if (write(ready[1], "x", 1) != 1 || read(release[0], &token, 1) != 1)
			_exit(1);
		_exit(0);
	}
	close(ready[1]);
	close(release[0]);
	if (read(ready[0], &token, 1) != 1)
		fail("child readiness");
	busy(200);
	if (ioctl(fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP))
		fail("disable");
	/* Drain the full ring so a later successful output publishes its loss. */
	stream_lost = lost_records(map, page, &samples);
	if (ioctl(fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP))
		fail("re-enable");
	busy(2);
	if (ioctl(fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP))
		fail("final disable");
	stream_lost += lost_records(map, page, &samples);
	live = read_lost(fd, group);
	if (write(release[1], "x", 1) != 1 || waitpid(child, &status, 0) != child ||
	    !WIFEXITED(status) || WEXITSTATUS(status))
		fail("child release");
	exited = read_lost(fd, group);
	printf("{\"group\":%d,\"samples\":%u,\"record_lost\":%llu,",
	       group, samples, (unsigned long long)stream_lost);
	printf("\"read_lost_child_alive\":%llu,", (unsigned long long)live);
	printf("\"read_lost_child_exited\":%llu}\n", (unsigned long long)exited);
	close(ready[0]);
	close(release[1]);
	munmap(map, page * 2);
	close(member);
	close(fd);
	return stream_lost == 0;
}
