#ifndef SYSCALL_H
#define SYSCALL_H

#include "annot.h"


long perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags); 
int bpf_prog_load(const struct bpf_insn* insns, int insn_cnt); 
int bpf_map_create(enum bpf_map_type type, int key_sz, int val_sz, int entries);
int bpf_map_update(int fd, void* key, void* val, int flags);

int tracepoint_setup(ebpf_t* e, int id);
#endif
