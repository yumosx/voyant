#ifndef ANNOT_H
#define ANNOT_H

#include <linux/bpf.h>
#include <stdio.h>

#include "ast.h"
#include "bpflib.h"
#include "symtable.h"
#include "buffer.h"

extern void get_annot(node_t *n, ebpf_t *e);
extern void loc_assign(node_t *n, ebpf_t *e);
extern void sema(node_t *n, ebpf_t *e);
#endif
