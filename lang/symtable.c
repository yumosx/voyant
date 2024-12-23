#include <stddef.h>
#include <stdlib.h>

#include "symtable.h"
#include "ut.h"

static void sym_init(symtable_t *st) {
    sym_t *sym;

    sym = &st->table[st->len++];
    sym->vannot.type = TYPE_INT;
    sym->vannot.size = 8;
    sym->name = "#";
}

symtable_t *symtable_new() {
    symtable_t *st;

    st = vmalloc(sizeof(*st));
    st->cap = 16;
    st->table = vcalloc(st->cap, sizeof(*st->table));

    sym_init(st);

    return st;
}

symtable_t* symtable_create(symtable_t* out) {
    symtable_t* st;

    st = vmalloc(sizeof(*st));
    st->cap = 16;
    st->table = vcalloc(st->cap, sizeof(*st->table));
    st->out = out;

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
        verror("invalid node type provided");
    }

    if (n->type == NODE_MAP){
        node_t* args;

        args = n->map.args;
        args->annot.type = sym->map->ktype;
        args->annot.addr = sym->map->kaddr;
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

void var_dec(symtable_t* st, node_t* var, node_t* expr) {
    char* name;
    sym_t* sym;

    name = var->name;
    
    sym = symtable_get(st, name);
    
    if (sym) {
        verror("Variable '%s' is already defined.", name);
    }

    sym = symtable_add(st, name);
    sym->type = SYM_VAR;
    sym->vannot = var->annot;
    
    if (expr->annot.type == TYPE_CAST) {
        sym->cast = expr->cast.name;
        sym->vannot.offs = expr->annot.offs;
    }
    
    sym->var = var;    
}


smap_t* map_create(node_t* map) {
    ssize_t ksize, vsize;
    smap_t* smap;

    ksize = map->annot.ksize;
    vsize = map->annot.size;

    map->annot.mapid = bpf_map_create(
        BPF_MAP_TYPE_HASH, ksize, vsize, 1024);

    smap = calloc(1, sizeof(*smap));

    smap->ksize = ksize;
    smap->vsize = vsize;
    smap->ktype = map->map.args->annot.type;
    smap->id = map->annot.mapid;
    smap->map = map;

    return smap;
}

void map_dec(symtable_t* st, node_t* map, node_t* expr) {
    sym_t* sym;
    char* name;
    smap_t* smap;

    name = map->name;
    sym = symtable_get(st, name);
    
    if (sym) {
        verror("map '%s' is already defined.", name);
    }

    smap = map_create(map);
    
    sym = symtable_add(st, name);
    sym->type = SYM_MAP;
    sym->vannot = map->annot;
    sym->map = smap;
}

int sym_ref(symtable_t* st, node_t* var) {
    sym_t* sym;

    sym = symtable_get(st, var->name);

    if (sym) {
        sym_transfer(sym, var);
        return 0; 
    }

    return -1;    
}

int symtable_ref(symtable_t* st, node_t* n) {
    switch (n->type) {
    case NODE_VAR:
        return sym_ref(st, n);
    case NODE_MAP:
       return sym_ref(st, n);
    default:
        break;
    }
}