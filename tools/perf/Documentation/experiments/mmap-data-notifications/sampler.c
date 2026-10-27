// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct stream { int fd; void *map; };
int main(int argc, char **argv)
{
    if (argc != 4 && argc != 5) { fprintf(stderr,"usage: sampler MMAP_FLAG START_PID TID,TID,... [PERCPU_COUNT]\n"); return 1; }
    struct stream streams[4096]; int n=0, flag=atoi(argv[1]);
    int cpus=argc==5 ? atoi(argv[4]) : 0;
    struct rlimit limit;getrlimit(RLIMIT_NOFILE,&limit);limit.rlim_cur=limit.rlim_max<8192?limit.rlim_max:8192;setrlimit(RLIMIT_NOFILE,&limit); size_t page=sysconf(_SC_PAGESIZE), capacity=page*8;
    int start_pid=atoi(argv[2]), tids=1;
    for(char *c=argv[3]; *c; c++) if(*c==',') tids++;
    if(start_pid<=0 || (flag!=0 && flag!=1) || cpus<0 || cpus>4096 || tids>4096/(cpus?cpus:1)) return 1;
    char *word=strtok(argv[3],",");
    while (word && n<4096) {
      if(atoi(word)<=0) return 1;
      for(int cpu=0; cpu<(cpus ? cpus : 1); cpu++) {
        struct perf_event_attr attr = { .type=PERF_TYPE_HARDWARE, .size=sizeof(attr), .config=PERF_COUNT_HW_CPU_CYCLES,
            .sample_freq=199, .sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_TID|PERF_SAMPLE_TIME|PERF_SAMPLE_PERIOD,
            .disabled=1, .freq=1, .exclude_user=1, .exclude_hv=1, .exclude_callchain_user=1,
            .mmap=flag, .mmap2=flag, .mmap_data=0, .comm=1, .task=1, .wakeup_events=1 };
        int fd=syscall(SYS_perf_event_open,&attr,atoi(word),cpus ? cpu : -1,-1,PERF_FLAG_FD_CLOEXEC);
        if(fd<0){perror("perf_event_open");return 1;}
        void *map=mmap(NULL,page+capacity,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
        if(map==MAP_FAILED){perror("perf ring mmap");return 1;}
        streams[n++]=(struct stream){fd,map};
      }
      word=strtok(NULL,",");
    }
    if(!n || word)return 1;
    for(int i=0;i<n;i++) if(ioctl(streams[i].fd,PERF_EVENT_IOC_ENABLE,0)){perror("enable");return 1;}
    if(kill(start_pid,SIGUSR1)){perror("start");return 1;}
    struct timespec interval={1,700000000};nanosleep(&interval,NULL);
    unsigned long samples=0, lost=0, mmap_events=0;
    for(int i=0;i<n;i++) {
        ioctl(streams[i].fd,PERF_EVENT_IOC_DISABLE,0);
        struct perf_event_mmap_page *meta=streams[i].map;
        uint64_t head=__atomic_load_n(&meta->data_head,__ATOMIC_ACQUIRE), tail=meta->data_tail;
        char *data=(char *)meta+page;
        if(head-tail>capacity){fprintf(stderr,"ring overflow\n");return 1;}
        while(tail<head) {
            struct perf_event_header header;memcpy(&header,data+(tail%capacity),sizeof(header));
            if(header.size<sizeof(header)||header.size>capacity){fprintf(stderr,"invalid header\n");return 1;}
            if(header.type==PERF_RECORD_SAMPLE)samples++;
            if(header.type==PERF_RECORD_MMAP||header.type==PERF_RECORD_MMAP2)mmap_events++;
            if(header.type==PERF_RECORD_LOST) {
                uint64_t amount;size_t pos=(tail+16)%capacity;
                if(pos+8<=capacity)memcpy(&amount,data+pos,8);
                else{size_t first=capacity-pos;memcpy(&amount,data+pos,first);memcpy((char *)&amount+first,data,8-first);}
                lost+=amount;
            }
            tail+=header.size;
        }
        __atomic_store_n(&meta->data_tail,head,__ATOMIC_RELEASE);
        munmap(meta,page+capacity);close(streams[i].fd);
    }
    printf("SAMPLER mmap=%d mmap_data=0 events=%d samples=%lu lost=%lu mmap_records=%lu\n",flag,n,samples,lost,mmap_events);
    return !!lost;
}
