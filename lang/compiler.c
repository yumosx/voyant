#include <stdint.h>

#include "compiler.h"

void ebpf_emit(ebpf_t* e, struct bpf_insn insn) {
    *(e->ip)++ = insn;
}

void reg_value_load(node_t* n, ebpf_t* e, reg_t* r) {
	switch (n->type) {
	case NODE_INT:
		ebpf_emit(e, MOV_IMM(r->reg, n->integer));
		break;
	default:
		break;
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

void str_to_stack(ebpf_t* e, void* data, ssize_t at, size_t size) {
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


void compile_func_call(node_t* n, ebpf_t* e) {
	if (!strcmp(n->name, "pid")) {
		compile_pid(n, e);
	} else if (!strcmp(n->name, "cpu")) {
		compile_cpu(n, e);
	} else {
		_errmsg("not match the function call");
	}
}

void call_to_stack(node_t* n, ebpf_t* e, ssize_t* at) {
	reg_t* reg;
	
	compile_func_call(n, e);
	reg = reg_bind_find(n, e);

	ebpf_emit(e, MOV(BPF_REG_0, reg->reg));
	ebpf_emit(e, STXDW(BPF_REG_10, at, BPF_REG_0));
}

void sym_to_stack(node_t* n, ebpf_t* e, size_t addr) {
	sym_t* sym;

	sym = symtable_get(e->st, n->name);
	
	if (sym->reg) {
		ebpf_emit(e, MOV(BPF_REG_0, sym->reg->reg));
		ebpf_emit(e, STXDW(BPF_REG_10, addr, BPF_REG_0));
	}
}

void rec_to_stack(node_t* n, ebpf_t* e) {
	node_t* arg;
	ssize_t offs = 0;

	offs = n->annot.addr;
		
	_foreach(arg, n->rec.args) {
		switch (arg->type) {
		case NODE_INT:
			int_to_stack(e, arg->integer, offs);
			break;
		case NODE_STRING:
			str_to_stack(e, arg->name, offs, arg->annot.size);
			break;
		case NODE_CALL:
			call_to_stack(arg, e, offs);
			break;
		case NODE_VAR:
			sym_to_stack(arg, e, offs);
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

void emit_map_look(ebpf_t* e, int fd, ssize_t key) {
	emit_ld_mapfd(e, BPF_REG_1, fd);
	
	ebpf_emit(e, MOV(BPF_REG_2, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_2, key));

	ebpf_emit(e, CALL(BPF_FUNC_map_lookup_elem));
}


void compile_map_assign(node_t* n, ebpf_t* e) {
   node_t* lval, *expr;
   ssize_t size;

   lval = n->assign.lval, expr = n->assign.expr;
	
   ebpf_emit(e, ALU_IMM(n->assign.op, BPF_REG_0, lval->map.args->integer));       
   ebpf_emit(e, STXDW(BPF_REG_10, lval->annot.addr + lval->annot.size, BPF_REG_0));   
   
   if (expr->annot.type == NODE_INT && expr->type == NODE_INT) {
	   ebpf_emit(e, ALU_IMM(n->assign.op, BPF_REG_0, expr->integer));       
       ebpf_emit(e, STXDW(BPF_REG_10, lval->annot.addr, BPF_REG_0));   
   }
	
	size = lval->annot.addr + lval->annot.size;
	emit_map_update(e, lval->annot.mapid, size, lval->annot.addr);
}

void map_load(node_t* head, ebpf_t* e) {
	sym_t* sym = symtable_get(e->st, head->name);    

    head->annot = sym->annot;

    int at = head->annot.addr + head->annot.size; 
    
    //TODO: just has one args
	//ebpf_emit(e, MOV(BPF_REG_0, 10));
    ebpf_emit(e, STXDW(BPF_REG_10, at, BPF_REG_0));

    emit_ld_mapfd(e, BPF_REG_1, head->annot.mapid);
    ebpf_emit(e, MOV(BPF_REG_2, BPF_REG_10));
    ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_2, head->annot.addr)); 
    ebpf_emit(e, CALL(BPF_FUNC_map_lookup_elem));
    
    ebpf_emit(e, JMP_IMM(JUMP_JEQ, BPF_REG_0, 0, 5));

    ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_10));
    ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_1, head->annot.addr));
    ebpf_emit(e, MOV_IMM(BPF_REG_2, head->annot.size));
    ebpf_emit(e, MOV(BPF_REG_3, BPF_REG_0));
    
    ebpf_emit(e, CALL(BPF_FUNC_probe_read));
    //ebpf_emit(e, JMP_IMM(JUMP_JA, 0, 0, head->annot.size / 4));

    for (int i = 0; i < (ssize_t)head->annot.size; i += 4) {
        ebpf_emit(e, STW_IMM(BPF_REG_10, head->annot.addr + i, 0));
    }
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
		_errmsg("get register failed");

	ebpf_emit(e, MOV(dst->reg, 0));
    reg_bind(n, e, dst);
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

void compile_sym_assign(node_t* n, ebpf_t* e) {
	reg_t* dst;

	dst = reg_get(e);
	
	reg_value_load(n->assign.expr, e, dst);
	reg_bind(n->assign.lval, e, dst);
}

void compile_str(node_t* n, ebpf_t* e) {
    str_to_stack(e, n->annot.addr, n->name, n->annot.size);
}

void compile_return(node_t* n, ebpf_t* e) {
	ebpf_emit(e, MOV_IMM(BPF_REG_0, 0));
	ebpf_emit(e, EXIT);
	return 0;
}