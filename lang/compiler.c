#include <stdio.h>

void statck_init(node_t* n, ebpf_t* e) {
	size_t i;
	ebpf_emit(e, MOV_IMM(BPF_REG_0, 0));
	
	for (int i = 0; i < n->annot.size; i += sizeof(int64_t)) {
		ebpf_emit(e, STXDW(BPF_REG_10, n->annot.addr + i, BPF_REG_0));	
	}
}


static int 
compile_read(node_t* n, ebpf_t* e) {
	node_t* addr = n->call.args;
	stack_init(n, e);	
	ebpf_emit();
	ebpf_emit();
}


void compile_call(node_t* n, ebpf_t* e) {
	char* name;
	name = n->name;

	if (!strcmp()) {


	}
}
