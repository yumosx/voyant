#ifndef DSL_H
#define DSL_H

#include <linux/bpf.h>
#include <stdio.h>

#include "lexer.h"
#include "insn.h"
#include "parser.h"
#include "ast.h"
#include "symtable.h"


#define get_mode_name(probe)  mode_str[probe.mode]

typedef struct ebpf_t {
    symtable_t* st;
    struct bpf_insn prog[BPF_MAXINSNS];
    struct bpf_insn* ip;
}ebpf_t;

#endif
