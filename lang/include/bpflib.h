#ifndef BPF_LIB_H
#define BPF_LIB_H

#include <linux/bpf.h>

#include "buffer.h"
#include "symtable.h"
#include "ast.h"
#include "ut.h"

typedef struct ebpf_t{
    ssize_t sp;
    symtable_t *st;
    evpipe_t *evp;
    struct bpf_insn *ip;
    struct bpf_insn prog[BPF_MAXINSNS];
    struct reg_t reg[__MAX_BPF_REG];
} ebpf_t;

extern ebpf_t *ebpf_new();
extern ssize_t stack_addr_get(node_t* n, ebpf_t* e);
extern reg_t* reg_get(ebpf_t* e); 
extern void reg_bind(node_t* n, ebpf_t* e, reg_t* r);
extern reg_t* reg_bind_find(node_t* n, ebpf_t* e);
#endif