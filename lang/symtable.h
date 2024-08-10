#ifndef SYMTABLE_H
#define SYMTABLE_H

#include "ast.h"

typedef struct sym sym_t;

typedef struct reg_t {
    int start;
    int end;
    enum {
        BPF_REG_EMPTY,
        BPF_REG_NODE,
        BPF_REG_SYM,
    } type;

    union {
        node_t *node;
        sym_t *sym;
    };

    int reg;
} reg_t;

typedef struct sym {
    const char *name;
    annot_t annot;
    ssize_t addr;
    ssize_t size;
    ssize_t ksize;
    reg_t *reg;
} sym_t;

typedef struct symtable_t{
    size_t cap, len;
    sym_t *table;
    ssize_t sp;
} symtable_t;

symtable_t *symtable_new();
sym_t *symtable_get(symtable_t *st, const char *name);
int sym_transfer(symtable_t *st, node_t *n);
void symtable_add(symtable_t *st, node_t *n);

#endif
