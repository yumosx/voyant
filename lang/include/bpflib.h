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
} ebpf_t;

extern ebpf_t *ebpf_new();
extern ssize_t stack_addr_get(node_t* n, ebpf_t* e);
#endif