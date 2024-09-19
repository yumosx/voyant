#ifndef ANNOT_H
#define ANNOT_H

#include <linux/bpf.h>
#include <stdio.h>

#include "ast.h"
#include "bpflib.h"
#include "symtable.h"
#include "buffer.h"
#include "probe.h"

#define xor(_a, _b) (!!(_a) ^ (!!(_b)))

#define _annot(_node, _type, _size)  \
    do                               \
    {                                \
        _node->annot.type = _type;   \
        _node->annot.size = (_size); \
    } while (0)

#define _annot_map(_node, _type, _ksize, _size) \
    do                                          \
    {                                           \
        _node->annot.type = _type;              \
        _node->annot.ksize = _ksize;            \
        _node->annot.size = (_size);            \
    } while (0)

#define _na_type(_node) _node->annot.type
#define _na_size(_node) _node->annot.size

extern void get_annot(node_t *n, ebpf_t *e);
extern void loc_assign(node_t *n, ebpf_t *e);
extern void sema(node_t *n, ebpf_t *e);
#endif
