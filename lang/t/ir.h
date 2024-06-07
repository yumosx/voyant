#ifndef IR_H
#define IR_H

typedef enum {
    jmp,
    je,
    jne,
} opcode_t;


typedef enum {
    reg,
    stack,
    index,    
} oprandk_t;


typedef struct oprand_t {
    oprandk_t kind;
    node_t* value;   
} oprand_t;


typedef struct insn_t {
    int len;
    opcode_t opcode;
    oprand_t oprand[2];
    insn_t* next;
} ir_insn_t;


typedef struct ir {
    symtable_t* symtable;
    int next;
} ir_t;


typedef struct basicblock_t{
    insn_t* insn;        
} basicblock_t;

#endif
