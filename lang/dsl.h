#ifndef DSL_H
#define DSL_H

#include <linux/bpf.h>
#include <stdio.h>

#include "lexer.h"
#include "insn.h"
#include "parser.h"
#include "ast.h"

#define get_mode_name(probe)  mode_str[probe.mode]

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
node_t* parse_probe_pred(parser_t* p);


void node_walk(node_t* n, ebpf_t* e);

int get_tracepoint_id(char* name);


void compile_str(ebpf_t* e, node_t* n);
int compile_pid_call(ebpf_t* e, node_t* n);

void get_annot(node_t* n, ebpf_t* e);
void annot_comm(node_t* n);

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
