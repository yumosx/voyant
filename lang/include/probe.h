#ifndef SYSCALL_H
#define SYSCALL_H

#include "annot.h"

typedef struct profile {
    int* efds;
    int num;
} profile_t;




extern long perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags); 
extern int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn* insns, int insn_cnt); 
extern int bpf_map_create(enum bpf_map_type type, int key_sz, int val_sz, int entries);
extern int bpf_map_update(int fd, void* key, void* val, int flags);
extern int bpf_map_lookup(int fd, void* key, void* val);
extern int bpf_read_field(field_t* field);
extern int bpf_test_attach(ebpf_t* e);
extern int bpf_get_probe_id(char* name);
extern int bpf_get_kprobe_id(char* name);
extern int bpf_probe_attach(ebpf_t* e, int id);
extern int bpf_kprobe_attach(ebpf_t* ctx, int id);
#endif
