#include "bpflib.h"

ebpf_t* ebpf_new() {
    ebpf_t* e = vcalloc(1, sizeof(*e));
    
	e->st = symtable_new();     
	e->ip = e->prog;
    e->evp = vcalloc(1, sizeof(*e->evp));
	
	for (int i = BPF_REG_0; i < __MAX_BPF_REG; i++) {
		*(int*)(&e->reg[i].reg) = i;
		*(int*)(&e->reg[i].type) = BPF_REG_EMPTY;
	}
		
	return e;
}

ssize_t stack_addr_get(node_t* n, ebpf_t* e) {
	
	if (n->type == NODE_MAP) {
		e->sp -= n->annot.ksize;
	}
	
	e->sp -= n->annot.size;
	return e->sp;
}

reg_t* reg_get(ebpf_t* e) {
	reg_t* r;
	
	for (r = &e->reg[BPF_REG_8]; r >= &e->reg[BPF_REG_6]; r--) {
		if (r->type == BPF_REG_EMPTY) {
			return r;
		}
	}

	return NULL;
}

void reg_bind(node_t* n, ebpf_t* e, reg_t* r) {
	if (n->type == NODE_VAR) {
		sym_t* sym;
		sym = symtable_get(e->st, n->name);
		sym->reg = r;
		r->type = BPF_REG_SYM;
		r->sym = sym;
	} else {
		r->type = BPF_REG_NODE;
		r->node = n;
	}
}

reg_t* reg_bind_find(node_t* n, ebpf_t* e) {
	reg_t* reg;
	int type;
	sym_t* sym;

	type = BPF_REG_NODE;

	if (n->type == NODE_VAR) {
		sym = symtable_get(e->st, n->name);
		type = BPF_REG_SYM;
	}

	for (reg = &e->reg[BPF_REG_8]; reg >= &e->reg[BPF_REG_6]; reg--) {
		if (reg->type == BPF_REG_NODE && reg->node == n) {
			return reg;
		}
		if (reg->type == BPF_REG_SYM && reg->sym == sym) {
			return reg;
		}
	}
}
