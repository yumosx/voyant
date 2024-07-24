#ifndef COMPILER_H
#define COMPILER_H

#include <stdio.h>
#include <linux/bpf.h>

#include "insn.h"
#include "ast.h"
#include "annot.h"

typedef struct func_t {
    char* name;
    void (*compile)(node_t* n, ebpf_t* e);
} func_t;

extern void ebpf_emit(ebpf_t* e, struct bpf_insn insn);
extern void emit_ld_mapfd(ebpf_t* e, int reg, int fd);
extern void stack_push(ebpf_t* e, ssize_t at, void* data, size_t size);
extern void rec_to_stack(node_t* n, ebpf_t* e);
extern void compile_out(node_t* n, ebpf_t* e);
#endif