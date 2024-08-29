#ifndef DSL_H
#define DSL_H

#include <linux/bpf.h>
#include <stdio.h>

#include "lexer.h"
#include "insn.h"
#include "parser.h"
#include "ast.h"
#include "symtable.h"
#include "annot.h"

extern void compile_walk(node_t* n, ebpf_t* e);

#endif
