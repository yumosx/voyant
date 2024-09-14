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

void ebpf_stack_zero(node_t* value, ebpf_t* code, int reg) {
	size_t i;
	annot_t to;
	size_t size;

	to = value->annot;
	size = to.size;

	ebpf_emit(code, MOV_IMM(reg, 0));

	for (i = 0; i < size; i += sizeof(int64_t)) {
		ebpf_emit(code, STXDW(BPF_REG_10, to.addr + i, reg));
	}
}

void ebpf_str_to_stack(ebpf_t* code, node_t* value) {
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

void ebpf_value_copy(ebpf_t* code, ssize_t to, ssize_t from, size_t size) {
	while (size >= 8) {
		ebpf_emit(code, LDXDW(BPF_REG_0,  from, BPF_REG_10));
		ebpf_emit(code, STXDW(BPF_REG_10, to, BPF_REG_0));

		to += 8;
		from += 8;
		size -= 8;
	}

	if (size >= 4) {
		ebpf_emit(code, LDXW(BPF_REG_0,  from, BPF_REG_10));
		ebpf_emit(code, STXW(BPF_REG_10, to,   BPF_REG_0));
		to += 4;
		from += 4;
		size -= 4;
	}

	if (size >= 2) {
		ebpf_emit(code, LDXH(BPF_REG_0,  from, BPF_REG_10));
		ebpf_emit(code, STXH(BPF_REG_10, to,   BPF_REG_0));
		to += 2;
		from += 2;
		size -= 2;
	}

	if (size) {
		ebpf_emit(code, LDXB(BPF_REG_0, from, BPF_REG_10));
		ebpf_emit(code, STXB(BPF_REG_10, to, BPF_REG_0));
	}
}