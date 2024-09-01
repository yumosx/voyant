#ifndef ANNOT_H
#define ANNOT_H

#include <linux/bpf.h>
#include <stdio.h>

#include "ast.h"
#include "bpflib.h"
#include "symtable.h"
#include "buffer.h"

typedef struct infer_fn_t {
    node_type_t type; 

    int(*annot_fn)(node_t* n, ebpf_t* e);
    int(*assign_fn)(node_t* n, ebpf_t* e);
} infer_fn_t;

extern void get_annot(node_t *n, ebpf_t *e);
extern void loc_assign(node_t *n, ebpf_t *e);

typedef void (*pre_t) (node_t* n, ebpf_t* ctx);
typedef void (*post_t) (node_t* n, ebpf_t* ctx);

void visit(node_t *n, pre_t pre, post_t post, ebpf_t *e);
#endif
