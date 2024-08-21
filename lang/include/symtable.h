#ifndef SYMTABLE_H
#define SYMTABLE_H

#include "ast.h"

typedef struct reg_t reg_t;

typedef enum {
    SYM_MAP,
    SYM_VAR,
} sym_type;

typedef struct sym {
    const char *name;
    sym_type type;
    
    ssize_t addr;
    annot_t vannot;
    reg_t *reg;
    node_t* node;
} sym_t;

typedef struct reg_t {
    int start;
    int end;
    
    enum {
        BPF_REG_EMPTY,
        BPF_REG_NODE,
        BPF_REG_SYM,
    } type;

    union
    {
        node_t *node;
        sym_t *sym;
    };

    int reg;
} reg_t;

typedef struct symtable_t {
    size_t cap, len;
    sym_t *table;
    ssize_t sp;
} symtable_t;

extern symtable_t *symtable_new();
extern sym_t *symtable_get(symtable_t *st, const char *name);
extern int sym_transfer(symtable_t *st, node_t *n);

extern void sym_annot(symtable_t* st, sym_type type, node_t* value);
extern void symtable_add(symtable_t* st, char* n);

#endif
