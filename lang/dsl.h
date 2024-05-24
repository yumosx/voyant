#ifndef DSL_H
#define DSL_H

#include <linux/bpf.h>
#include <stdio.h>

#include "lexer.h"
#include "insn.h"
#include "parser.h"


typedef struct node_t node_t;
typedef struct probe_t probe_t;

typedef enum node_type_t {
    NODE_SCRIPT,
    NODE_PROBE,
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


#define get_node_name(n) node_str[n->type]

typedef struct annot_t {
    node_type_t type;
    loc_t loc;
    int reg;
    int mapid;
    size_t keysize;
    ssize_t size;
    ssize_t addr;
} annot_t;


typedef enum mode_type_t {
   PROBE_USER,
   PROBE_SYS,
} mode_type_t;


#define get_mode_name(probe)  mode_str[probe.mode]

typedef struct script_t{
    node_t* probes;
} script_t;


typedef struct probe_t {
    mode_type_t mode;
    node_t* ident;
    node_t* stmts;
}probe_t;


typedef struct call_t {
   node_t* args; 
} call_t;


typedef struct infix_t {
    op_t op;
    node_t* left, *right;
} infix_t;

typedef struct prefix_t {
    op_t op;
    node_t* right;
} prefix_t;


typedef struct assign_t {
    op_t op;
    node_t* lval, *expr;
} assign_t;

typedef struct let_stmts {
    node_t* expr;
} let_stmts_t;


typedef struct map_t {
    node_t* args; 
} map_t;


typedef struct node_t{
    node_type_t type;
    node_t* prev, *next;
    node_t* parent;
    char* name;

    union {
        script_t script;
        probe_t probe;
        infix_t infix_expr;
        prefix_t prefix_expr;
        call_t call;
        map_t map;
        let_stmts_t let_stmts; 
        assign_t assign;
        size_t integer;
    };

    annot_t annot;
} node_t;


typedef struct program_t {
    node_t* node;
} program_t;


typedef struct sym_t sym_t;

typedef struct reg_t {
    const int reg;
        
    enum{
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


typedef struct sym_t {
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


typedef struct ebpf_t {
    symtable_t* st;
    struct bpf_insn prog[BPF_MAXINSNS];
    struct bpf_insn* ip;
}ebpf_t;


parser_t* parser_init(lexer_t* l);
node_t* parse_block_stmts(parser_t* p);
node_t* parse_probe(parser_t* p);
node_t* parse_expr(parser_t* p, seq_t s);
node_t* parse_int_expr(char* name);
node_t* parse_program(parser_t* p);
node_t* parse_let_stmts(parser_t* p);

int get_tracepoint_id(char* name);

void node_walk(node_t* n, ebpf_t* e);

void compile_str(ebpf_t* e, node_t* n);
int compile_pid_call(ebpf_t* e, node_t* n);


void get_annot(node_t* n, ebpf_t* e);

void compile_map_load(node_t* n, ebpf_t* e);
void compile_call_(node_t* n, ebpf_t* e);
void compile_call(ebpf_t* e, node_t* n);
void compile_print(node_t* n, ebpf_t* e);
 
void compile_map_assign(node_t* n, ebpf_t* e);
void compile_map(node_t* a, ebpf_t* e); 

void ebpf_emit(ebpf_t* e, struct bpf_insn insn); 
int bpf_map_create(enum bpf_map_type type, int key_sz, int val_sz, int entries); 
void emit_ld_mapfd(ebpf_t* e, int reg, int fd); 


reg_t* ebpf_reg_get(ebpf_t* e);
void ebpf_reg_load(ebpf_t* e, reg_t* r, node_t* n);
int ebpf_reg_bind(ebpf_t* e, reg_t* r, node_t* n);

int tracepoint_setup(ebpf_t* e, int id);

ebpf_t* ebpf_new();
symtable_t* symtable_new();

int symtable_transfer(symtable_t* s, node_t* n);
void symtable_add(symtable_t* s, node_t* n);
#endif
