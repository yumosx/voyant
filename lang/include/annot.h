#ifndef ANNOT_H
#define ANNOT_H

#include <linux/bpf.h>
#include <stdio.h>

#include "ast.h"
#include "bpflib.h"
#include "symtable.h"
#include "buffer.h"
#include "probe.h"

#define _annot_map(_node, _type, _ksize, _size) \
    do                                          \
    {                                           \
        _node->annot.type = _type;              \
        _node->annot.ksize = _ksize;            \
        _node->annot.size = (_size);            \
    } while (0)


extern void get_annot(node_t *n, ebpf_t *e);
extern void loc_assign(node_t *n, ebpf_t *e);
extern void sema(node_t *n, ebpf_t *e);
#endif
