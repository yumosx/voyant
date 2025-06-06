#ifndef AST_H
#define AST_H

#include <unistd.h>
#include <stdbool.h>
#include "insn.h"

typedef enum node_type{
    NODE_SCRIPT,
    NODE_PROBE,
    NODE_KPROBE,
    NODE_TEST,
    NODE_PROBE_PRED,
    NODE_IF,
    NODE_UNROLL,
    NODE_PREFIX_EXPR,
    NODE_EXPR,
    NODE_LOGAND,
    NODE_LOGOR,
    NODE_DEC,
    NODE_VAR,
    NODE_MAP,
    NODE_REC,
    NODE_ASSIGN,
    NODE_CALL,
    NODE_STR,
    NODE_INT,
    NODE_CAST,
} node_type;

typedef struct node_t node_t;

typedef enum {
    PRODE_KPROBE,
    PROBE_PROBE,
} probe_type;

typedef struct probe_t {
    char *name;
    int traceid;
    node_t* stmts;
} probe_t;

typedef struct call_t {
    node_t *args;
} call_t;

typedef struct infix_t {
    int opcode;
    node_t *left, *right;
} infix_t;

typedef struct prefix_t {
    int opcode;
    node_t *right;
} prefix_t;

typedef struct assign_t {
    op_t op;
    node_t *lval, *expr;
} assign_t;

typedef struct map_t {
    node_t *args;
} map_t;

typedef struct rec_t {
    node_t *args;
} rec_t;

typedef struct iff_t {
    node_t *cond;
    node_t *then;
    node_t *els;
} iff_t;

typedef struct unroll_t {
    size_t count;
    node_t *stmts;
} unroll_t;

typedef struct dec_t {
    node_t *var;
    node_t *expr;
} dec_t;

typedef enum loc_t {
    LOC_NOWHERE,
    LOC_REG,
    LOC_STACK,
} loc_t;

typedef enum type_t {
    TYPE_SCRIPT,
    TYPE_PROBE,
    TYPE_KPROBE,
    TYPE_TEST,
    TYPE_PROBE_PRED,
    TYPE_IF,
    TYPE_UNROLL,
    TYPE_PREFIX_EXPR,
    TYPE_EXPR,
    TYPE_LOGAND,
    TYPE_LOGOR,
    TYPE_DEC,
    TYPE_VAR,
    TYPE_MAP,
    TYPE_REC,
    TYPE_ASSIGN,
    TYPE_CALL,
    TYPE_STR,
    TYPE_CAST,
    TYPE_INT,
    TYPE_MAP_METHOD,
    TYPE_NULL,
} type_t;

typedef struct annot_t {
    type_t type;
    int mapid;
    int isarg;
    size_t ksize;
    ssize_t size;
    size_t offs;

    loc_t loc;
    ssize_t addr;
} annot_t;

typedef struct field_t{
    char* name;
    char* field;
    type_t type; 
    size_t offs;
} field_t;

typedef struct cast_t{
    char* name, *value;
} cast_t;

struct node_t {
    char *name;
    node_type type;
    node_t *parent, *next;

    union{
        probe_t probe;
        infix_t expr;
        prefix_t pexpr;
        dec_t dec;
        iff_t iff;
        unroll_t unroll;
        call_t call;
        map_t map;
        rec_t rec;
        cast_t cast;
        assign_t assign;
        size_t integer;
    };

    annot_t annot;
};


extern node_t *node_new(node_type t);
extern node_t *node_probe_new(char *name, node_t *stmts);
extern node_t *node_kprobe_new(char *name, node_t *stmts);
extern node_t *node_test_new(char* name, node_t* stmts);
extern node_t *node_var_new(char *name);
extern node_t *node_int_new(size_t name);
extern node_t *node_str_new(char *str);
extern node_t *node_expr_new(int opcode, node_t *left, node_t *right);
extern node_t *node_if_new(node_t *cond, node_t *then, node_t *els);
extern node_t *node_unroll_new(size_t count, node_t *stmts);
extern node_t *node_rec_new(node_t *args);
extern node_t *node_assign_new(node_t *left, node_t *expr);
extern node_t *node_dec_new(node_t *var, node_t *expr);
extern node_t *node_cast_new(char* name, char* value);
extern void free_node(node_t* node);

#endif
