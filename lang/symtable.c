#include <stddef.h>
#include <stdlib.h>
#include "symtable.h"
#include "ut.h"

static void sym_init(symtable_t *st)
{
    sym_t *sym;

    sym = &st->table[st->len++];
    sym->annot.type = ANNOT_INT;
    sym->annot.size = 8;
    sym->name = "@$";
    sym->size = sym->annot.size;
}

symtable_t *symtable_new() {
    symtable_t *st;

    st = checked_malloc(sizeof(*st));
    st->cap = 16;
    st->table = checked_calloc(st->cap, sizeof(*st->table));

    sym_init(st);

    return st;
}

sym_t *symtable_get(symtable_t *st, const char *name)
{
    size_t i;

    for (i = 0; i < st->len; i++)
    {
        if (!strcmp(st->table[i].name, name))
        {
            return &st->table[i];
        }
    }

    return NULL;
}

int sym_transfer(symtable_t *st, node_t *n) {
    sym_t *sym;

    if (n->type != NODE_VAR && n->type != NODE_MAP) {
        return 0;
    }

    sym = symtable_get(st, n->name);
    n->annot = sym->annot;

    return 0;
}

int symtable_map_transfer(symtable_t *st, node_t *m) {
    node_t *n, *head;

    head = m->map.args;
    
    _foreach(n, head) {
        sym_transfer(st, n);
    }

    return 0;
}

void symtable_add(symtable_t *st, node_t *n) {
    sym_t *sym;

    if (st->len == st->cap) {
        st->cap += 16;
        st->table = realloc(st->table, st->cap * sizeof(*st->table));
        memset(&st->table[st->len], 0, 16 * sizeof(*st->table));
    }

    sym = &st->table[st->len++];
    sym->name = n->name;
    sym->annot = n->annot;
    sym->size = n->annot.size;

    if (n->type == NODE_MAP) {
        sym->ksize = n->annot.keysize;
    }
}