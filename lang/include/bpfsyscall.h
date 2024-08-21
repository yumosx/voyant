#ifndef SYSCALL_H
#define SYSCALL_H

#include "annot.h"

typedef struct vprobe {
    FILE* ctrl;
    const char* ctrl_name;
    char* pattern;
} vprobe_t; 


typedef void (*fn_t)(void);


extern long perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags); 
extern int bpf_prog_load(const struct bpf_insn* insns, int insn_cnt); 
extern int bpf_prog_test_run(int prog_fd);
extern int bpf_map_create(enum bpf_map_type type, int key_sz, int val_sz, int entries);
extern int bpf_map_update(int fd, void* key, void* val, int flags);
extern int bpf_map_lookup(int fd, void* key, void* val);
extern int tracepoint_setup(ebpf_t* e, int id);
#endif
