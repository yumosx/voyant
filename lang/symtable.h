#ifndef SYMTABLE_H
#define SYMTABLE_H

#include "ast.h"

typedef struct sym sym_t;

typedef struct reg {
    const int reg;
    
    enum {
        REG_EMPTY,
        REG_SYM,
        REG_NODE,
    }type;

    int age;

    union {
        void* obj;
        sym_t* sym;
        node_t* n;
    };
} reg_t;



typedef struct sym {
    const char* name;
    annot_t annot;
    ssize_t addr;
    ssize_t size;
    node_t* keys;
    reg_t* reg;
} sym_t;


typedef struct symtable_t {
    size_t cap, len;
    sym_t* table;
    reg_t reg[__MAX_BPF_REG];
    ssize_t stack_top;
} symtable_t;


symtable_t* symtable_new();
ssize_t symtable_reserve(symtable_t* st, size_t size); 
sym_t* symtable_get(symtable_t* st, const char* name); 
int symtable_transfer(symtable_t* st, node_t* n); 
#endif
