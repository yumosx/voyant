#ifndef IR_H
#define IR_H

#include "lexer.h"
#include "ast.h"
#include "parser.h"
#include "annot.h"

enum
{
    IR_ADD = 1,
    IR_SUB,
    IR_MUL,
    IR_DIV,
    IR_GT,
    IR_GE,
    IR_IMM,
    IR_STR,
    IR_MOV,
    IR_RETURN,
    IR_CALL,
    IR_RCALL,
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
    IR_IF_THEN,
    IR_IF_END,
    IR_ELSE_THEN,
    IR_ELSE_END,
    IR_MAP_UPDATE,
    IR_MAP_LOOK,
    IR_REC,
    IR_INIT,
    IR_LOAD,
    IR_COPY,
    IR_PUSH,
    IR_STW,
    IR_LOAD_SPILL,
    IR_STORE,
    IR_STORE_ARG,
    IR_STORE_SPILL,
    IR_NOP,
};

typedef struct reg_t
{
    int vn;
    int rn;
    int def;
    int end;
    bool spill;
    char *str;
} reg_t;

typedef struct bb_t
{
    int label;
    vec_t *ir;
    reg_t *parm;

    vec_t *succ;
    vec_t *pred;
    vec_t *def_regs;
    vec_t *in_regs;
    vec_t *out_regs;
} bb_t;

typedef struct ir_t
{
    int op;
    reg_t *r0;
    reg_t *r1;
    reg_t *r2;

    int imm;
    int label;
    node_t *value;
    bb_t *bb1;
    bb_t *bb2;

    ssize_t addr;
    char *name;
    int nargs;
    reg_t *args[5];

    vec_t *kill;
    reg_t *bbarg;
} ir_t;

typedef struct prog_t
{
    char *name;
    node_t *ast;
    vec_t *data;
    vec_t *bbs;
    ebpf_t *e;
} prog_t;

extern reg_t *gen_expr(node_t *n);
extern void gen_stmt(node_t *n);
extern void gen_store(node_t *dst, node_t *src);
extern int gen_ir(node_t *n);
extern prog_t *gen_prog(node_t *n);
extern void compile(prog_t* prog);
#endif