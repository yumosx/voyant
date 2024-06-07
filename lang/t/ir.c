#include "ir.h"

oprand_t* create_oprand(oprandk_t kind, node_t* value) {
    oprand_t* oprand = malloc(sizeof(*oprand));
    oprand->kind = kind;
    oprand->value = value;
    return oprand;
}

insn_t* create_insn0(opcode_t op) {
    insn_t* insn = malloc(sizeof(*insn));
    insn->len = 0;
    insn->opcode = op;
    
    return insn;
}


insn_t* create_insn1(opcode_t op, oprand_t* oprand) {
    insn_t* insn = malloc(sizeof(*insn));
    insn->len = 1;
    insn->opcode = op;
    insn->oprand[0] = oprand;

    return insn;
}


insn_t* create_insn2(opcode_t op, oprand_t* op1, oprand_t* op2) {
    insn_t* insn = malloc(sizeof(*insn));
    insn->len = 2;
    insn->opcode = op;
    insn->oprand[0] = op1;
    insn->oprand[1] = op2; 

    return insn;
}


int istemp(oprand_t* op, int len) {
    return op->kind == varindex && op->value.index >= len;
}


void compile_ir(node_t* n, basic_block_t b) {
    switch(n->type) {
       case NODE_PROBE:
        break;
    }
}


void compile_binop(node_t* n, basic_block_t* b) {
    oprand_t* left = compile(n->infix_expr.left, b);
    oprand_t* right = compile(n->infix_expr.right, b);
    
    if (!istemp(left, n->infix_expr.index)) {
        //emit a temp value
    }
    
    if (istemp(right, n->index)) {
        dead(n->index);
    }

    switch () {

    }
}


oprand_t* oprand_to_int(node_t* n) {
    return create_oprand(imm, n);
}


oprand_t* oprand_to_str(node_t* n) {
    return create_oprand(strconst, n);
}

