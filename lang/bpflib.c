#include <assert.h>

#include "bpflib.h"

ebpf_t* ebpf_new() {
    ebpf_t* e = vcalloc(1, sizeof(*e));
    
	e->st = symtable_new();     
	e->ip = e->prog;
    e->evp = vcalloc(1, sizeof(*e->evp));
		
	return e;
}

void ebpf_emit(ebpf_t* code, struct bpf_insn insn) {
    assert(code != NULL);
    *(code->ip)++ = insn;
}

void ebpf_emit_at(struct bpf_insn* at, struct bpf_insn insn) {
	assert(at != NULL);
	*at = insn;
}

void ebpf_emit_mapld(ebpf_t* e, int reg, int fd) {
	ebpf_emit(e, INSN(BPF_LD|BPF_DW|BPF_IMM, reg, BPF_PSEUDO_MAP_FD, 0, fd));
    ebpf_emit(e, INSN(0, 0, 0, 0, 0));
}

ssize_t ebpf_addr_get(node_t* value, ebpf_t* code) {
	code->sp -= value->annot.size;
	return code->sp;
}

void ebpf_stack_zero(node_t* value, ebpf_t* code) {
	size_t i;
	annot_t to;
	size_t size;

	to = value->annot;
	size = to.size;

	ebpf_emit(code, MOV_IMM(BPF_REG_0, 0));

	for (i = 0; i < size; i += sizeof(int64_t)) {
		ebpf_emit(code, STXDW(BPF_REG_10, to.addr + i, BPF_REG_0));
	}
}

static void int_to_stack(ebpf_t* e, node_t* value) {
	ebpf_emit(e, MOV_IMM(BPF_REG_0, value->integer));
	ebpf_emit(e, STXDW(BPF_REG_10, value->annot.addr, BPF_REG_0));
}

static void str_to_stack(ebpf_t* code, node_t* value) {
	ssize_t size, at, left;
    int32_t* str;

    at = value->annot.addr;
    size = value->annot.size;
    str = value->name;
    left = size / sizeof(*str);
    
    for (; left; left--, str++, at += sizeof(*str)) {
        ebpf_emit(code, STW_IMM(BPF_REG_10, at, *str));
    }
}

static void rec_to_stack(ebpf_t* code, node_t* value) {
	node_t* arg;

	_foreach(arg, value->rec.args) {
		ebpf_value_to_stack(code, arg);
	}	
}

void ebpf_value_to_stack(ebpf_t* e, node_t* value) {
	switch (value->type) {
	case NODE_INT:
		int_to_stack(e, value);		
		break;
	case NODE_STR:
		str_to_stack(e, value);
		break;
	case NODE_REC:
		rec_to_stack(e, value);	
		break;
	default:
		break;
	}
}