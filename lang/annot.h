#ifndef ANNOT_H
#define ANNOT_H

#include <linux/bpf.h>
#include <stdio.h>

#include "ast.h"
#include "symtable.h"
#include "buffer.h"

typedef struct ebpf_t {
    symtable_t* st;
    evpipe_t* evp;
    struct bpf_insn* ip;
    struct bpf_insn prog[BPF_MAXINSNS];
    struct reg_t reg[__MAX_BPF_REG];
    int bindex;
}ebpf_t;

extern ebpf_t* ebpf_new();
extern ssize_t get_stack_addr(node_t* n, ebpf_t* e);
extern reg_t* reg_get(ebpf_t* e);
extern reg_t* reg_bind_find(node_t* n, ebpf_t* e);
extern void reg_bind(node_t* n, ebpf_t* e, reg_t* reg);
extern void get_annot(node_t* n, ebpf_t* e);
#endif
