#include "ir.h"


void emit() {

}


int compile(ir_t* ir, char* ret) {
    int r0 = ir->r0 ? ir->r0->rn : 0;
    int r1 = ir->r1 ? ir->r1->rn : 0;
    int r2 = ir->r2 ? ir->r2->rn : 0;

    switch (ir->op) {
    case IR_IMM:
        break;
    default:
        break;
    }

}