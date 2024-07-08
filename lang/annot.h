#ifndef ANNOT_H
#define ANNOT_H

typedef struct ebpf_t {
    symtable_t* st;
    struct bpf_insn prog[BPF_MAXINSNS];
    struct bpf_insn* ip;
}ebpf_t;


extern void get_annot(node_t* n, ebpf_t* e);

#endif
