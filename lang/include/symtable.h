#ifndef SYMTABLE_H
#define SYMTABLE_H

#include <stdbool.h>
#include "ast.h"

typedef enum
{
    SYM_NONE,
    SYM_MAP,
    SYM_VAR,
} sym_type;

typedef struct smap_t
{
    int id;
    enum bpf_map_type type;
    size_t ksize, vsize, nelem;
    ssize_t kaddr;
    node_t *map;
} smap_t;

typedef struct sym
{
    sym_type type;
    const char *name;
    annot_t vannot;

    union
    {
        node_t *var;
        smap_t *map;
    };
} sym_t;

typedef struct symtable_t
{
    size_t cap, len;
    sym_t *table;
    struct symtable_t *out;
} symtable_t;

extern symtable_t *symtable_new();
extern symtable_t *symtable_create(symtable_t *out);
extern sym_t *symtable_get(symtable_t *st, const char *name);
extern int sym_transfer(sym_t *st, node_t *n);
extern void var_dec(symtable_t *st, char *name, node_t *value);
extern void map_dec(symtable_t *st, node_t *n);
extern sym_t *symtable_add(symtable_t *st, char *name);
extern void symtable_ref(symtable_t *st, node_t *n);

#endif
