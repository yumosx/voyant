#include "bpflib.h"

ebpf_t* ebpf_new() {
    ebpf_t* e = vcalloc(1, sizeof(*e));
    
	e->st = symtable_new();     
	e->ip = e->prog;
    e->evp = vcalloc(1, sizeof(*e->evp));
		
	return e;
}

ssize_t stack_addr_get(node_t* n, ebpf_t* e) {
	if (n->type == NODE_MAP) {
		e->sp -= n->annot.ksize;
	}
	
	e->sp -= n->annot.size;
	return e->sp;
}