#ifndef COMPILER_H
#define COMPILER_H

#include <stdio.h>
#include <linux/bpf.h>

#include "insn.h"
#include "ast.h"
#include "annot.h"
#include "ut.h"

extern void ebpf_emit(ebpf_t* e, struct bpf_insn insn);
extern void emit_ld_mapfd(ebpf_t* e, int reg, int fd);

extern void str_to_stack(ebpf_t* e, void* data, ssize_t at, size_t size);
extern void rec_to_stack(node_t* n, ebpf_t* e);

extern void compile_out(node_t* n, ebpf_t* e);
extern void compile_comm(node_t* n, ebpf_t* e);
extern int compile_pid(node_t* n, ebpf_t* e);
extern int compile_cpu(node_t* n, ebpf_t* e);
extern int compile_ns(node_t* n, ebpf_t* e);

extern void compile_func_call(node_t* n, ebpf_t* e);

//extern void compile_map_assign(node_t* n, ebpf_t* e);
extern void map_load(node_t* n, ebpf_t* e);
extern void compile_sym_assign(node_t* n, ebpf_t* e);
extern void compile_str(node_t* n, ebpf_t* e);
#endif
