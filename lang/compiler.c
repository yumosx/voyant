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

void int_to_stack(ebpf_t* e, int value, ssize_t at) {
	ebpf_emit(e, MOV_IMM(BPF_REG_0, value));
	ebpf_emit(e, STXDW(BPF_REG_10, at, BPF_REG_0));
}

void call_to_stack(node_t* n, ebpf_t* e) {
	if (!strcmp(n->name, "pid")) {
		compile_pid(n, e);
	} else if (!strcmp(n->name, "cpu")) {
		compile_cpu(n, e);
	}
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
			str_to_stack(e, offs, arg->name, arg->annot.size);
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

int compile_rint_func(enum bpf_func_id func, extract_op_t op, ebpf_t* e, node_t* n) {
	reg_t* dst;

	ebpf_emit(e, CALL(func));
    
    switch(op) {
        case EXTRACT_OP_MASK:
            ebpf_emit(e, ALU_IMM(OP_AND, BPF_REG_0, 0xffffffff));
            break;
        case EXTRACT_OP_SHIFT:
            ebpf_emit(e, ALU_IMM(OP_RSH, BPF_REG_0, 32));
            break;
		case EXTRACT_OP_DIV_1G:
			ebpf_emit(e, ALU_IMM(OP_DIV, BPF_REG_0, 1000000000));
        default:
            break;
    }
	dst = reg_get(e);

	if (!dst)
		_errno("get register failed");

	ebpf_emit(e, MOV(dst->reg, BPF_REG_0));
	ebpf_emit(e, STXDW(BPF_REG_10, n->annot.addr, BPF_REG_8));

   return 0; 
}

int compile_pid(node_t* n, ebpf_t* e) {
    return compile_rint_func(BPF_FUNC_get_current_pid_tgid, EXTRACT_OP_MASK, e, n);
}

int compile_ns(node_t* n, ebpf_t* e) {
	return compile_rint_func(BPF_FUNC_ktime_get_ns, EXTRACT_OP_DIV_1G, e, n);
}

int compile_cpu(node_t* n, ebpf_t* e) {
	return compile_rint_func(BPF_FUNC_get_smp_processor_id, EXTRACT_OP_NONE, e, n);
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


void compile_return(node_t* n, ebpf_t* e) {
	ebpf_emit(e, MOV_IMM(BPF_REG_0, 0));
	ebpf_emit(e, EXIT);
	return 0;
}