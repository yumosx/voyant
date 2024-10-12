#ifndef SYSCALL_H
#define SYSCALL_H

#include "annot.h"

typedef struct profile {
    int* efds;
    int num;
} profile_t;


typedef struct btf_t{
    void* raw_data;
    void* raw_data_swapped;
    __u32 raw_size;
    bool swapped_endian;
    struct btf_header* hdr;
    void* type_data;
    size_t types_data_cap;
    __u32* type_offs;
    size_t type_offs_cap;
    __u32 nr_types;
    struct btf* base_btf;
    int start_id;
    int start_str_off;
    void* strs_data;
    bool strs_deduped;
    bool owns_base;
    int fd;
    int ptr_sz;
} btf_t; 

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
