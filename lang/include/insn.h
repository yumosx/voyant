#ifndef INSN_H
#define INSN_H

#include <linux/bpf.h>
#include <stddef.h>
#include <inttypes.h>

#define _ALIGN sizeof(int64_t)
#define _ALIGNED(_size) (((_size) + _ALIGN - 1) & ~(_ALIGN - 1))

#define BPF_CTX_REG BPF_REG_9

#define INSN(_code, _dst, _src, _off, _imm) \
    ((struct bpf_insn){                     \
        .code = _code,                      \
        .dst_reg = _dst,                    \
        .src_reg = _src,                    \
        .off = _off,                        \
        .imm = _imm})

typedef enum extract
{
    EXTRACT_OP_NONE,
    EXTRACT_OP_MASK,
    EXTRACT_OP_SHIFT,
    EXTRACT_OP_DIV_1G,
} extract_op_t;

typedef enum op_t{
    OP_ADD,
    OP_SUB,
    OP_MUL,
    OP_DIV,
    OP_OR,
    OP_AND,
    OP_LSH,
    OP_RSH,
    OP_NEG,
    OP_MOD,
    OP_XOR,
    OP_MOV,
    OP_EQ,
    OP_GT,
    OP_GE,
    OP_NE,
    OP_JSGT,
    OP_JA,
    OP_PIPE,
} op_t;

#define MOV(_dst, _src) INSN(BPF_ALU64 | BPF_MOV | BPF_X, _dst, _src, 0, 0)
#define MOV_IMM(_dst, _imm) INSN(BPF_ALU64 | BPF_MOV | BPF_K, _dst, 0, 0, _imm)

#define EXIT INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define CALL(_imm) INSN(BPF_JMP | BPF_CALL, 0, 0, 0, _imm)

#define JMP(_op, _dst, _src, _off) INSN(BPF_JMP | BPF_OP((_op)) | BPF_X, _dst, _src, _off, 0)
#define JMP_IMM(_op, _dst, _imm, _off) INSN(BPF_JMP | BPF_OP((_op)) | BPF_K, _dst, 0, _off, _imm)

#define ALU(_op, _dst, _src) INSN(BPF_ALU64 | BPF_OP((_op)) | BPF_X, _dst, _src, 0, 0)
#define ALU_IMM(_op, _dst, _imm) INSN(BPF_ALU64 | BPF_OP((_op)) | BPF_K, _dst, 0, 0, _imm)

#define STW_IMM(_dst, _off, _imm) INSN(BPF_ST | BPF_SIZE(BPF_W) | BPF_MEM, _dst, 0, _off, _imm)
#define STXDW(_dst, _off, _src) INSN(BPF_STX | BPF_SIZE(BPF_DW) | BPF_MEM, _dst, _src, _off, 0)

#define LDXDW(_dst, _off, _src) INSN(BPF_LDX | BPF_SIZE(BPF_DW) | BPF_MEM, _dst, _src, _off, 0)
#define LDXB(_dst, _off, _src) INSN(BPF_LDX | BPF_SIZE(BPF_B) | BPF_MEM, _dst, _src, _off, 0)

#endif
