#ifndef BPF_LIB_H
#define BPF_LIB_H

#include <linux/bpf.h>

#include "buffer.h"
#include "symtable.h"
#include "ast.h"
#include "ut.h"

typedef struct ebpf_t{
    char* name;
    ssize_t sp;
    symtable_t *st;
    evpipe_t *evp;
    struct bpf_insn *ip;
    struct bpf_insn prog[BPF_MAXINSNS];
} ebpf_t;

extern ebpf_t *ebpf_new();
extern ssize_t ebpf_addr_get(node_t *n, ebpf_t *e);
extern void ebpf_emit_mapld(ebpf_t *e, int reg, int fd);
extern void ebpf_stack_zero(node_t *value, ebpf_t *code, int reg);
extern void ebpf_emit(ebpf_t *code, struct bpf_insn insn);
extern void ebpf_emit_at(struct bpf_insn *at, struct bpf_insn insn);
extern void ebpf_value_copy(ebpf_t* code, ssize_t to, ssize_t from, size_t size);
extern void ebpf_str_to_stack(ebpf_t *code, node_t *value);
extern void ebpf_emit_map_look(ebpf_t* code, int fd, ssize_t kaddr);
extern void ebpf_emit_map_update(ebpf_t* code, int fd, ssize_t kaddr, ssize_t vaddr);
extern void ebpf_emit_count(ebpf_t* code, ssize_t addr);
extern void ebpf_emit_bool(ebpf_t* code, int op, int r0, int r2);
extern void ebpf_emit_read(ebpf_t* code, ssize_t to, int from, size_t size);
extern void ebpf_emit_read_str(ebpf_t* code, ssize_t to, int from, size_t size);
#endif