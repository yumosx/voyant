#include <stddef.h>
#include <stdlib.h>
#include "symtable.h"
#include "ut.h"

static void sym_init(symtable_t *st) {
    sym_t *sym;

    sym = &st->table[st->len++];
    sym->vannot.type = ANNOT_INT;
    sym->vannot.size = 8;
    sym->name = "voyant";
}

symtable_t *symtable_new() {
    symtable_t *st;

    st = vmalloc(sizeof(*st));
    st->cap = 16;
    st->table = vcalloc(st->cap, sizeof(*st->table));

    sym_init(st);

    return st;
}

sym_t *symtable_get(symtable_t *st, const char *name) {
    size_t i;

    for (i = 0; i < st->len; i++) {
        if (!strcmp(st->table[i].name, name)) {
            return &st->table[i];
        }
    }

    return NULL;
}

int sym_transfer(sym_t* sym, node_t *n) {
    if (n->type != NODE_VAR && n->type != NODE_MAP) {
        error("invalid node type provided");
    }
    
    n->annot = sym->vannot;
    return 0;
}

sym_t* symtable_add(symtable_t* st, char* name) {
    sym_t* sym;

    if (st->len == st->cap) {
        st->cap += 16;
        st->table = realloc(st->table, st->cap * sizeof(*st->table));
        memset(&st->table[st->len], 0, 16 * sizeof(*st->table));
    }

    sym = &st->table[st->len++];
    sym->name = name;

    return sym;
}

void sym_annot(symtable_t* st, sym_type type ,node_t* value) {
    sym_t* sym;

    sym = symtable_get(st, value->name);
    sym->type = type;
    sym->vannot = value->annot;
}

void var_dec(symtable_t* st, node_t* var) {
    sym_t* sym;

    sym = symtable_add(st, var->name);
    sym->vannot = var->annot; 
    sym->var = var;
}

int var_ref(symtable_t* st, node_t* n) {
    sym_t* sym;

    sym = symtable_get(st, n->name);
    
    if (sym) {
        sym_transfer(sym, n);
    }

    return 0;    
}

void map_ref(symtable_t* st, node_t* n) {
    
}

void symtable_ref(symtable_t* st, node_t* n) {
    switch (n->type) {
    case NODE_VAR:
        var_ref(st, n);
        break;
    case NODE_MAP:
        break;
    default:
        break;
    }
}