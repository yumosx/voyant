#ifndef FUNC_H
#define FUNC_H

#include "ast.h"

typedef struct builtin_t {
    const char* name;
    int (*annotate)   (node_t* call);
} builtin_t;

int global_annot(node_t* call);

#endif