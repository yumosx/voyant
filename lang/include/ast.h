#ifndef AST_H
#define AST_H

#include "insn.h"
#include <unistd.h>

typedef struct node_t node_t;
typedef struct call_t call_t;
typedef struct infix_t infix_t;
typedef struct prefix_t prefix_t;
typedef struct assign_t assign_t;

typedef enum node_type_t {
    NODE_SCRIPT,
    NODE_PROBE,
    NODE_PROBE_PRED,
    NODE_IF,
    NODE_PREFIX_EXPR,
    NODE_INFIX_EXPR,
    NODE_VAR,
    NODE_MAP,
    NODE_REC, 
	NODE_ASSIGN,
    NODE_CALL,
    NODE_STRING,
    NODE_INT,
} node_type_t;


typedef struct probe_t {
    char* name;
    int traceid;
    node_t* stmts;
} probe_t;

struct call_t {
   node_t* args; 
};

struct infix_t {
    int opcode;
    node_t* left, *right;
};

struct prefix_t {
    int opcode;
    node_t* right;
};

struct assign_t {
    op_t op;
    node_t* lval, *expr;
};

typedef struct map_t {
    node_t* args;
} map_t;


typedef struct rec_t {
	node_t* args;
} rec_t;


typedef struct iff_t {
    node_t* cond;
    node_t* then, *then_last;
    node_t* els;
} iff_t;

typedef struct unroll_t {
    size_t count;
    node_t* stmts;
} unroll_t;

typedef struct maphdr {
	size_t keyszie;
	int mapid;
} maphdr_t;

typedef enum loc_t {
    LOC_NOWHERE,
    LOC_REG,
    LOC_STACK,
} loc_t;

typedef enum annot_type{
    ANNOT_STR,
    ANNOT_INT,
    ANNOT_REC,
    ANNOT_SYM,
    ANNOT_RINT,
    ANNOT_RSTR,
    ANNOT_SYM_MAP,
    ANNOT_SYM_ASSIGN,
    ANNOT_MAP_ASSIGN,
    ANNOT_MAP_METHOD,
} annot_type;

typedef struct annot_t {
    annot_type type;
    int mapid;
    size_t keysize;
    ssize_t size;
    loc_t loc;
    ssize_t addr;
    int reg;
} annot_t;

typedef struct mem_t {
    loc_t loc;
    ssize_t addr;
    int reg;
} mem_t;

struct node_t {
    char* name;
    node_type_t type;
    node_t* prev, *next;

    union {
        probe_t probe;
        infix_t infix_expr;
        prefix_t prefix_expr;
        iff_t iff;
        call_t call;
        map_t map;
        rec_t rec;
		assign_t assign;
        size_t integer;
    };

    annot_t annot;
    mem_t mem_t;
};

extern node_t* node_new(node_type_t t);
extern node_t* node_probe_new(char* name, node_t* stmts);
extern node_t* node_var_new(char* name);
extern node_t* node_int_new(size_t name);
extern node_t* node_str_new(char* str);
extern node_t* node_expr_new(int opcode, node_t* left, node_t* right);
extern node_t* node_if_new(node_t* cond, node_t* then, node_t* els);
extern node_t* node_rec_new(node_t* args);
extern node_t* node_assign_new(node_t* left, node_t* expr);
extern void node_print_str(node_type_t type);

#endif
