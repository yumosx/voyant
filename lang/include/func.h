#ifndef FUNC_H
#define FUNC_H

#include "ast.h"
#include "bpflib.h"

typedef struct builtin_t {
    const char *name;
    int (*annotate)(node_t *call);
    int (*compile)(node_t *call, ebpf_t *e);
} builtin_t;

#define builtin(_name, _annot, _compile)                 \
    {.name = _name, .annotate = _annot, .compile = _compile}  \

int global_annot(node_t *call);
int global_compile(node_t *n, ebpf_t *e);
#endif