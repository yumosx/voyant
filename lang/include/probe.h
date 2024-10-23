#ifndef SYSCALL_H
#define SYSCALL_H

#include "annot.h"
#include <linux/btf.h>

typedef struct profile {
    int* efds;
    int num;
} profile_t;

#define BTF_MAX_NR_TYPES 0x7fffffffU
#define BTF_MAX_STR_OFFSET 0x7fffffffU

static struct btf_type btf_void;

typedef struct btf_t{
    void* raw_data;
    void* raw_data_swapped;
    __u32 raw_size;
    bool swapped_endian;
    struct btf_header* hdr;
    void* types_data;
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

static inline __u16 btf_vlen(const struct btf_type *t) {
	return BTF_INFO_VLEN(t->info);
}

static inline __u16 btf_kind(const struct btf_type *t) {
	return BTF_INFO_KIND(t->info);
}

static inline struct btf_enum* btf_enum(const struct btf_type* t)
{
    return (struct btf_enum*)(t + 1);
}

static inline struct btf_member* btf_members(const struct btf_type* t) 
{
    return (struct btf_member*)(t + 1);
}

static inline struct btf_param* btf_params(const struct btf_type* t) {
    return (struct btf_param*)(t + 1);
}

static inline struct btf_var_secinfo* btf_var_secinfos(const struct btf_type* t)
{
    return (struct btf_var_secinfo*)(t + 1);
}


static inline struct btf_array* btf_array(const struct btf_type* t) {
    return (struct btf_array*)(t + 1);
}

static inline struct btf_var *btf_var(const struct btf_type *t)
{
	return (struct btf_var *)(t + 1);
}

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
extern btf_t* btf_load_vmlinux();
extern int btf_get_field_off(const char *struct_name, const char *field_name);
#endif
