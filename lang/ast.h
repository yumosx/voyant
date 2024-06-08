#ifndef AST_H
#define AST_H

#include "insn.h"

typedef enum node_type_t {
    NODE_SCRIPT,
    NODE_PROBE,
    NODE_PROBE_PRED,
    NODE_PREFIX_EXPR,
    NODE_INFIX_EXPR,
    NODE_EXPR,
    NODE_VAR,
    NODE_MAP,
    NODE_LET,
    NODE_ASSIGN,
    NODE_CALL,
    NODE_STRING,
    NODE_INT,
} node_type_t;

typedef struct node_t node_t;

typedef struct probe_t {
    char* name;
    int traceid;
    node_t* stmts;
} probe_t;


typedef struct call_t {
   node_t* args; 
} call_t;


typedef struct infix_t {
    int opcode;
    node_t* left, *right;
} infix_t;


typedef struct prefix_t {
    int opcode;
    node_t* right;
} prefix_t;


typedef struct assign_t {
    op_t op;
    node_t* lval, *expr;
} assign_t;


typedef struct map_t {
    node_t* args;
} map_t;


typedef struct annot_t {
    node_type_t type;
    int reg;
    int mapid;
    size_t keysize;
    ssize_t size;
    ssize_t addr;
    loc_t loc;
} annot_t;


typedef struct node_t {
    node_type_t type;
    node_t* prev, *next;
    char* name;

    union 
    {
        probe_t probe;
        infix_t infix_expr;
        prefix_t prefix_expr;
        call_t call;
        map_t map;
        assign_t assign;
        size_t integer;
    };

    annot_t annot;
} node_t;

node_t* node_new(node_type_t t);
node_t* node_new_var(char* name);
node_t* node_int_new(char* name);
node_t* node_str_new(char* str);

#endif
