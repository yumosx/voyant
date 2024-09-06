#include <stdint.h>
#include <assert.h>

#include "compiler.h"
#include "func.h"

void ebpf_emit(ebpf_t* e, struct bpf_insn insn) {
	assert(e != NULL);
	*(e->ip)++ = insn;
}

void reg_value_load(node_t* n, ebpf_t* e, xreg_t* r) {
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

void sym_to_stack(node_t* n, ebpf_t* e, size_t addr) {
	sym_t* sym;

	sym = symtable_get(e->st, n->name);
	
	if (sym->reg) {
		ebpf_emit(e, MOV(BPF_REG_0, sym->reg->reg));
		ebpf_emit(e, STXDW(BPF_REG_10, addr, BPF_REG_0));
	}
}

void compile_arg(node_t* arg, ebpf_t* e) {
	switch (arg->type) {
		case NODE_INT:
			int_to_stack(e, arg->integer, arg->annot.addr);
			break;
		case NODE_STRING:
			str_to_stack(e, arg->name, arg->annot.addr, arg->annot.size);
			break;
		case NODE_VAR:
			sym_to_stack(arg, e, arg->annot.addr);
			break;
		case NODE_CALL:
			global_compile(arg, e);
			break;
		case NODE_MAP:
			compile_map_load(arg, e);
		default:
			break;
	}
}

void compile_rec(node_t* n, ebpf_t* e) {
	node_t* arg;

	_foreach(arg, n->rec.args) {
		compile_arg(arg, e);
	}
}

void emit_ld_mapfd(ebpf_t* e, int reg, int fd) {
    ebpf_emit(e, INSN(BPF_LD|BPF_DW|BPF_IMM, reg, BPF_PSEUDO_MAP_FD, 0, fd));
    ebpf_emit(e, INSN(0, 0, 0, 0, 0));
}

void compile_out(node_t* n, ebpf_t* e) {
	compile_rec(n, e);

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

int emit_map_look(ebpf_t *prog, int fd, ssize_t addr) {
	
	emit_ld_mapfd(prog, BPF_REG_1, fd);
	ebpf_emit(prog, MOV(BPF_REG_2, BPF_REG_10));
	ebpf_emit(prog, ALU_IMM(BPF_ADD, BPF_REG_2, addr));
	ebpf_emit(prog, CALL(BPF_FUNC_map_lookup_elem));
	
	return 0;
}

void emit_read(ebpf_t* e, ssize_t to, int from, size_t size) {
	ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(BPF_ADD, BPF_REG_1, to));
	ebpf_emit(e, MOV_IMM(BPF_REG_2, size));
	ebpf_emit(e, MOV(BPF_REG_3, from));
	ebpf_emit(e, CALL(BPF_FUNC_probe_read));
}

void compile_count(ssize_t addr, ebpf_t* e) {
	ebpf_emit(e, LDXB(BPF_REG_0, addr, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(BPF_ADD, BPF_REG_0, 1));
	ebpf_emit(e, STXDW(BPF_REG_10, addr, BPF_REG_0));
}

void compile_map_method(node_t* n, ebpf_t* e) {
	node_t* left, *right, *key;
	size_t kaddr, vaddr;
	int fd;

	left = n->infix_expr.left;
	key = left->map.args;
	right = n->infix_expr.right;

	kaddr = left->annot.addr;
	vaddr = kaddr + left->annot.ksize;
	fd = left->annot.mapid;

	compile_arg(key, e);
	int_to_stack(e, 0, vaddr);	

	emit_map_look(e, fd, kaddr);
	ebpf_emit(e, JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 8));	
	
	emit_read(e, vaddr, BPF_REG_0, 8);	
	compile_count(vaddr, e);
	emit_map_update(e, fd, kaddr, vaddr);
}

void compile_map_assign(node_t* n, ebpf_t* e) {
	node_t* val, *expr;
	size_t kaddr, vaddr;
	int fd;

	val = n->assign.lval;	
	expr = n->assign.expr;
	
	kaddr = val->annot.addr;
	vaddr = kaddr + val->annot.size;
	fd = val->annot.mapid;

	int_to_stack(e, val->map.args->integer, kaddr);	
	int_to_stack(e, expr->integer, vaddr);
	
	emit_map_update(e, val->annot.mapid, kaddr, vaddr);
}

void compile_sym_assign(node_t* n, ebpf_t* e) {
	node_t* var, *expr;
	xreg_t* dst;

	switch (n->type) {
	case NODE_DEC:
		var = n->dec.var; 
		expr = n->dec.expr;
		break;
	case NODE_ASSIGN:
		var = n->assign.lval;
		expr = n->assign.expr;
		break;
	default:
		break;
	}

	dst = reg_bind_find(var, e);
	reg_value_load(expr, e, dst);
}

void compile_map_load(node_t* n, ebpf_t* e) {
	sym_t* sym;
	size_t kaddr = 0;
	size_t size;
	int fd;

	sym = symtable_get(e->st, n->name);
	
	if (!sym) {
		verror("map not found");
	}
	
	kaddr = sym->addr;
	fd = sym->vannot.mapid;
	size = sym->vannot.size;

	int_to_stack(e, 0, n->annot.addr);	
	emit_map_look(e, fd, kaddr);
	ebpf_emit(e, JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 5));
	emit_read(e, n->annot.addr, BPF_REG_0, 8);
}

void compile_str(node_t* n, ebpf_t* e) {
    str_to_stack(e, n->annot.addr, n->name, n->annot.size);
}

void compile_return(node_t* n, ebpf_t* e) {
	ebpf_emit(e, MOV_IMM(BPF_REG_0, 0));
	ebpf_emit(e, EXIT);
	return 0;
}