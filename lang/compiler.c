#include <stdint.h>

#include "compiler.h"

void ebpf_emit(ebpf_t* e, struct bpf_insn insn) {
	*(e->ip)++ = insn;
}

reg_t* reg_get(ebpf_t* e) {
    reg_t* r, *r_aged = NULL;

    for (r = &e->st->reg[BPF_REG_8]; r >= &e->st->reg[BPF_REG_0]; r--) {
       if (r->type == REG_EMPTY) {
            return r;
       } 

       if (r->type == REG_SYM && (!r_aged || r->age < r_aged->age)) {
            r_aged = r;
       }
    }
}

void stack_init(node_t* n, ebpf_t* e) {
	size_t i;
	annot_t to = n->annot;
	size_t len = to.size;
	
	ebpf_emit(e, MOV_IMM(BPF_REG_0, 0));
	
	for (i = 0; i < len; i += sizeof(int64_t)) {
		ebpf_emit(e, STXDW(BPF_REG_10, to.addr+i, BPF_REG_0));	
	}
}

void str_to_stack(ebpf_t* e, ssize_t at, void* data, size_t size) {
	uint32_t* obj = data;
	size_t left = size / sizeof(*obj);
	
	for (; left; left--, obj++, at += sizeof(*obj)) {
		ebpf_emit(e, STW_IMM(BPF_REG_10, at, *obj));
	}
}

void str_to_stack_(ebpf_t* e, ssize_t start, void* data, size_t size) {
	const int32_t* s32 = data;
	ssize_t at;

	for (at = start; size; at += sizeof(*s32), size -= sizeof(*s32), s32++) {
		ebpf_emit(e, STW_IMM(BPF_REG_10, at, *s32));	
	}
}

void int_to_stack(ebpf_t* e, int value, ssize_t at) {
	ebpf_emit(e, MOV_IMM(BPF_REG_0, value));
	ebpf_emit(e, STXDW(BPF_REG_10, at, BPF_REG_0));
}

void call_to_stack(node_t* n, ebpf_t* e) {
	compile_comm(n, e);
}

void rec_to_stack(node_t* n, ebpf_t* e) {
	node_t* arg;
	ssize_t offs = 0;

	offs = n->annot.addr;
	
	for (arg = n->rec.args; arg; arg = arg->next) {
		switch (arg->type) {
		case NODE_INT:
			int_to_stack(e, arg->integer, offs);
			break;
		case NODE_STRING:
			str_to_stack_(e, offs, arg->name, arg->annot.size);
			break;
		case NODE_CALL:
			call_to_stack(arg, e);
			break;
		default:
			break;
		}

		offs += arg->annot.size;
	}
}

void emit_ld_mapfd(ebpf_t* e, int reg, int fd) {
    ebpf_emit(e, INSN(BPF_LD|BPF_DW|BPF_IMM, reg, BPF_PSEUDO_MAP_FD, 0, fd));
    ebpf_emit(e, INSN(0, 0, 0, 0, 0));
}

void compile_out(node_t* n, ebpf_t* e) {
	rec_to_stack(n, e);

	annot_t to = n->annot;
	int id = e->evp->mapfd;

	ebpf_emit(e, CALL(BPF_FUNC_get_smp_processor_id));
	ebpf_emit(e, MOV(BPF_REG_3, BPF_REG_0));
	
	ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_9));
	emit_ld_mapfd(e, BPF_REG_2, id);	
	
	ebpf_emit(e, MOV(BPF_REG_4, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_4, to.addr));

	ebpf_emit(e, MOV_IMM(BPF_REG_5, to.size));
	ebpf_emit(e, CALL(BPF_FUNC_perf_event_output));
}

void emit_map_update(ebpf_t* e, int fd, ssize_t key, ssize_t value) {
   	emit_ld_mapfd(e, BPF_REG_1, fd);
	ebpf_emit(e, MOV(BPF_REG_2, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_2, key));
   
	ebpf_emit(e, MOV(BPF_REG_3, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_3, value));

	ebpf_emit(e, MOV_IMM(BPF_REG_4, 0));
	ebpf_emit(e, CALL(BPF_FUNC_map_update_elem));
}


void compile_map_assign(node_t* n, ebpf_t* e) {
   node_t* lval = n->assign.lval, *expr = n->assign.expr;
	//store args
   ebpf_emit(e, ALU_IMM(n->assign.op, BPF_REG_0, lval->map.args->integer));       
   ebpf_emit(e, STXDW(BPF_REG_10, lval->annot.addr + lval->annot.size, BPF_REG_0));   
   //store value
   if (expr->annot.type == NODE_INT && expr->type == NODE_INT) {
	   ebpf_emit(e, ALU_IMM(n->assign.op, BPF_REG_0, expr->integer));       
       ebpf_emit(e, STXDW(BPF_REG_10, lval->annot.addr, BPF_REG_0));   
   }
	
	ssize_t size = lval->annot.addr + lval->annot.size;
	emit_map_update(e, lval->annot.mapid, size, lval->annot.addr);
}


void compile_comm(node_t* n, ebpf_t* e) {
	size_t i;
	
	for (i = 0; i < n->annot.size; i += 4) {
		ebpf_emit(e, STW_IMM(BPF_REG_10, n->annot.addr+i, BPF_REG_0));
	}

	ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_1, n->annot.addr));
	ebpf_emit(e, MOV_IMM(BPF_REG_2, n->annot.size));
	ebpf_emit(e, CALL(BPF_FUNC_get_current_comm));
}
