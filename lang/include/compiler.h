#ifndef COMPILER_H
#define COMPILER_H

#include <stdio.h>
#include <linux/bpf.h>

#include "insn.h"
#include "ast.h"
#include "annot.h"
#include "bpflib.h"
#include "ut.h"


extern void ebpf_emit(ebpf_t* e, struct bpf_insn insn);

#endif
