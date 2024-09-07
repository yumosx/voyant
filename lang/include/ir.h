#ifndef IR_H
#define IR_H

#include "lexer.h"
#include "ast.h"
#include "parser.h"
#include "annot.h"

enum {
  IR_ADD = 1,
  IR_SUB,
  IR_MUL,
  IR_DIV,
  IR_IMM,
  IR_STR,
  IR_MAP,
  IR_BPREL,
  IR_MOV,
  IR_RETURN,
  IR_CALL,
  IR_LABEL_ADDR,
  IR_EQ,
  IR_NE,
  IR_LE,
  IR_LT,
  IR_AND,
  IR_OR,
  IR_XOR,
  IR_SHL,
  IR_SHR,
  IR_MOD,
  IR_JMP,
  IR_BR,
  IR_LOAD,
  IR_LOAD_SPILL,
  IR_STORE,
  IR_STORE_ARG,
  IR_STORE_SPILL,
  IR_NOP,
  IR_VAR_DEC,
};

typedef struct reg_t {
    int vn;
    int rn;
    int def;
    int end;

    bool issp;    
    bool spill;
    
    char* str;
    node_t* var;
} reg_t;

typedef struct bb_t {
    int label;
    vec_t* ir;
    reg_t* parm;

    vec_t* succ;
    vec_t* pred;
    vec_t* def_regs;
    vec_t* in_regs;
    vec_t* out_regs;
} bb_t;

typedef struct ir_t {
    int op;
    reg_t* r0;
    reg_t* r1;
    reg_t* r2;

    int imm;
    int label;
    node_t* var;
    bb_t* bb1;
    bb_t* bb2;

    int size;
    char* name;
    int nargs;
    reg_t* args[5];
    
    vec_t* kill;
    reg_t* bbarg;
} ir_t;

typedef struct prog_t{
    char* name;
    
    node_t* ast;
    vec_t* vars;
    vec_t* bbs;
    
    int sp;
} prog_t;

typedef struct code_t {
    struct bpf_insn* ip;
    struct bpf_insn prog[BPF_MAXINSNS];
} code_t;

reg_t* emit_expr(node_t* n);
int gen_ir(node_t* n);

#endif