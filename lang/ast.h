#ifndef AST_H
#define AST_H

#include "insn.h"

typedef struct node_t node_t;
typedef struct call_t call_t;
typedef struct infix_t infix_t;
typedef struct prefix_t prefix_t;
typedef struct assign_t assign_t;

typedef enum node_type_t {
    NODE_SCRIPT,
    NODE_PROBE,
    NODE_PROBE_PRED,
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


typedef struct maphdr {
	size_t keyszie;
	int mapid;
} maphdr_t;

typedef enum loc_t {
    LOC_NOWHERE,
    LOC_REG,
    LOC_STACK,
} loc_t;

typedef enum {
    ANNOT_SYM_MAP_INT,
    
    //sym = 1
    ANNOT_SYM_INT,
    ANOOT_SYM_STRING,

    ANNOT_RETURN_INT,
    ANNOT_RETURN_STR,
    ANNOT_STRING,
    ANNOT_INT,
} annot_type;


typedef struct annot_t {
    node_type_t type;
    annot_type atype;
    int mapid;
    size_t keysize;
    ssize_t size;
    loc_t loc;
    ssize_t addr;
    int reg;
} annot_t;


struct node_t {
    node_type_t type;
    node_t* prev, *next;
    char* name;

    union {
        probe_t probe;
        infix_t infix_expr;
        prefix_t prefix_expr;
        call_t call;
        map_t map;
        rec_t rec;
		assign_t assign;
        size_t integer;
    };

    annot_t annot;
};


extern node_t* node_new(node_type_t t);
extern node_t* node_probe_new(char* name, node_t* stmts);
extern node_t* node_new_var(char* name);
extern node_t* node_int_new(size_t name);
extern node_t* node_str_new(char* str);
extern node_t* node_expr_new(int opcode, node_t* left, node_t* right);
extern node_t* node_rec_new(node_t* args);
extern node_t* node_assign_new(node_t* left, node_t* expr);
extern void node_print_str(node_type_t type);

#endif
