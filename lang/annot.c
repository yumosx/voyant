#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "annot.h"
#include "func.h"
#include "ut.h"

static int annot_value(node_t *value) {
	int err = 0;
	
	switch (value->type) {
	case NODE_INT:
		_annot(value, TYPE_INT, sizeof(value->integer));
		break;
	case NODE_STR:
		_annot(value, TYPE_STR, _ALIGNED(strlen(value->name)+1));
		break;
	case NODE_CALL:
		err = global_annot(value);
		break;
	default:
		break;
	}

	return err;
}

static void annot_map(node_t *map, ebpf_t *e) {
	node_t *arg;
	ssize_t ksize;

	arg = map->map.args;
	get_annot(arg, e);
	ksize = arg->annot.size;

	_annot_map(map, TYPE_MAP, ksize, 8);
}

static int annot_dec(node_t *n, ebpf_t *e) {
	node_t *var, *expr;
	int err = 0;
	var = n->dec.var;
	expr = n->dec.expr;

	get_annot(expr, e);

	switch (var->type) {
	case NODE_VAR:
		_annot(var, TYPE_VAR, 8);
		var->annot.size = expr->annot.size;
		var_dec(e->st, var);
		break;
	case NODE_MAP:
		annot_map(var, e);
		var->annot.size = expr->annot.size;
		map_dec(e->st, var);
		break;
	default:
		verror("Declaration variable must be either a map or a variable");
		break;
	}

	n->annot.type = TYPE_DEC;
	return err;
}

void annot_probe_args(node_t* expr, ebpf_t* ctx) {
	size_t offs;
	field_t field;
	node_t* arg, *data; 

	data = expr->expr.right;
	
	field.name = ctx->name;
	field.field = data->name;

	bpf_read_field(&field);

	data->annot.type = field.type;
	data->annot.offs = field.offs;
	expr->annot.type = TYPE_ACCESS;

	switch (data->annot.type){
	case TYPE_INT:
		expr->annot.size = 8;
		break;
	case TYPE_STR:
		expr->annot.size = 64;
		break;
	default:
		break;
	}

}

int annot_map_method(node_t* expr, ebpf_t* ctx) {
	int err = 0;
	node_t* left, *right;

	left = expr->expr.left;
	right = expr->expr.right;

	annot_map(left, ctx);

	right->prev = left;
	map_dec(ctx->st, left);
	expr->annot.type = TYPE_MAP_METHOD;

	return err;
}

void annot_expr(node_t* expr, ebpf_t* ctx) {
	node_t* left, *right;
	int opcode;

	left   = expr->expr.left;
	right  = expr->expr.right;
	opcode = expr->expr.opcode;

	switch (opcode) {
	case OP_PIPE:
		annot_map_method(expr, ctx);
		break;
	case OP_ACCESS:
		annot_probe_args(expr, ctx);
		break;
	default:
		get_annot(left, ctx);
		get_annot(right, ctx);
		expr->annot.type = TYPE_EXPR;
		expr->annot.size = 8;
		break;
	}
}

void annot_rec(node_t *n, ebpf_t *e) {
	node_t *arg;
	ssize_t size = 0;

	_foreach(arg, n->rec.args) {
		get_annot(arg, e);
		size += arg->annot.size;
	}

	n->annot.size = size;
	n->annot.type = TYPE_REC;
}


void get_annot(node_t *n, ebpf_t *e) {
	switch (n->type) {
	case NODE_CALL:
	case NODE_INT:
	case NODE_STR:
		annot_value(n);
		break;
	case NODE_VAR:
	case NODE_MAP:
		symtable_ref(e->st, n);
		break;
	case NODE_EXPR:
		annot_expr(n, e);
		break;
	case NODE_DEC:
		annot_dec(n, e);
		break;
	case NODE_ASSIGN:
		break;
	case NODE_REC:
		annot_rec(n, e);
		break;
	default:
		break;
	}
}

void assign_stack(node_t *n, ebpf_t *e) {
	n->annot.addr = ebpf_addr_get(n, e);
}


void assign_data(node_t* node, ssize_t addr) {
	switch (node->annot.type) {
	case TYPE_STR:
		node->annot.addr = addr;
		break;
	case TYPE_RSTR:
		node->annot.addr = addr;
		break;
	case TYPE_VAR:
		node->annot.addr = addr;
		break;
	case TYPE_ACCESS:
		node->expr.left->annot.addr = addr;
		break;
	default:
		break;
	}

}

void assign_dec(node_t *dec, ebpf_t *code) {
	node_t *var, *expr;
	ssize_t addr;
	sym_t *sym;

	var = dec->dec.var;
	expr = dec->dec.expr;
	sym = symtable_get(code->st, var->name);
	
	if (var->type == NODE_MAP) {
		node_t *args;
		args = var->map.args;
		addr = ebpf_addr_get(args, code);

		args->annot.addr = addr;
		sym->map->kaddr = addr;
	}
	
	addr = ebpf_addr_get(var, code);
	var->annot.addr = addr;
	sym->vannot.addr = addr;

	assign_data(expr, addr);
}

void assign_rec(node_t *n, ebpf_t *e) {
	node_t *head;
	size_t offs;
	assign_stack(n, e);

	offs = n->annot.addr;

	_foreach(head, n->rec.args) {
		head->annot.addr = offs;
		offs += head->annot.size;
	}
}

void assign_method(node_t* expr, ebpf_t* code) {
	node_t* map, *args;
	sym_t* sym;
	ssize_t addr;
	
	map = expr->expr.left;
	args = map->map.args;
	sym = symtable_get(code->st, map->name);

	addr = ebpf_addr_get(args, code);

	args->annot.addr = addr;
	sym->map->kaddr = addr;

	addr = ebpf_addr_get(map, code);
	
	sym->vannot.addr = addr;
	map->annot.addr = addr;
}


void assign_rint(node_t* call, ebpf_t* code) {
	node_t* arg;

	if (vstreq(call->name, "strcmp")) {
		arg = call->call.args;
		arg->annot.addr = ebpf_addr_get(arg, code);

		arg = arg->next;
		arg->annot.addr = ebpf_addr_get(arg, code);
		return;	
	}
}

void loc_assign(node_t *node, ebpf_t *code) {
	switch (node->annot.type) {
	case TYPE_RSTR:
		assign_stack(node, code);
		break;
	case TYPE_RINT:
		assign_rint(node, code);
		break;
	case TYPE_DEC:
		assign_dec(node, code);
		break;
	case TYPE_REC:
		assign_rec(node, code);
		break;
	case TYPE_MAP_METHOD:
		assign_method(node, code);
		break;
	default:
		break;
	}
}

static int do_list(node_t *head, ebpf_t *ctx) {
	node_t *elem, *next = head;

	for (elem = next; elem;) {
		next = elem->next;
		sema(elem, ctx);
		elem = next;
	}

	return 0;
}

void sema(node_t *node, ebpf_t *ctx) {
	
	get_annot(node, ctx);
	
	switch (node->type) {
	case NODE_PROBE:
		ctx->name = node->probe.name;
		do_list(node->probe.stmts, ctx);
		break;
	case NODE_CALL:
		do_list(node->call.args, ctx);
		break;
	case NODE_IF:
		do_list(node->iff.cond, ctx);
		do_list(node->iff.then, ctx);
		break;
	default:
		break;
	}

	loc_assign(node, ctx);
}