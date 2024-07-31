#ifndef DSL_H
#define DSL_H

#include <linux/bpf.h>
#include <stdio.h>

#include "lexer.h"
#include "insn.h"
#include "parser.h"
#include "ast.h"
#include "symtable.h"
#include "testbase.h"
#include "annot.h"


#define get_mode_name(probe)  mode_str[probe.mode]

#endif
