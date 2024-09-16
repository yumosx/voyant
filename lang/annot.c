#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "annot.h"
#include "func.h"
#include "ut.h"

static void check_int(node_t *n) {
	node_type_t ty;

	ty = n->type;
	if (ty != NODE_INT) {
		verror("not an integer");
	}
}

static void annot_value(node_t *value) {
	switch (value->type) {
	case NODE_INT:
		value->annot.type = TYPE_INT;
		value->annot.size = sizeof(value->integer);
		break;
	case NODE_STR:
		value->annot.type = TYPE_STR;
		value->annot.size = _ALIGNED(strlen(value->name) + 1);
		break;
	default:
		verror("not an integer or string valuie");
		break;
	}
}

static void annot_var(node_t *var, ebpf_t *e) {
	var->annot.type = TYPE_VAR;
	var->annot.size = 8;
}

static void annot_map(node_t *map, ebpf_t *e) {
	node_t *arg;
	ssize_t ksize;

	arg = map->map.args;
	get_annot(arg, e);
	ksize = arg->annot.size;

	map->annot.type = TYPE_MAP;
	map->annot.size = 8;
	map->annot.ksize = ksize;
}

static void annot_dec(node_t *n, ebpf_t *e) {
	node_t *var, *expr;

	var = n->dec.var;
	expr = n->dec.expr;

	get_annot(expr, e);

	switch (var->type) {
	case NODE_VAR:
		annot_var(var, e);
		var->annot.size = expr->annot.size;
		var_dec(e->st, var);
		break;
	case NODE_MAP:
		annot_map(var, e);
		var->annot.size = expr->annot.size;
		map_dec(e->st, var);
		break;
	default:
		verror("left type is not map or variable");
		break;
	}

	n->annot.type = TYPE_DEC;
}

void annot_assign(node_t *n, ebpf_t *e) {
	node_t *var, *expr;

	var = n->assign.lval;
	expr = n->assign.expr;

	get_annot(expr, e);
	symtable_ref(e->st, var);
}

void annot_expr(node_t* expr, ebpf_t* e) {
	node_t* left, *right;
	int opcode;

	left   = expr->expr.left;
	right  = expr->expr.right;
	opcode = expr->expr.opcode;

	switch (opcode) {
	case OP_PIPE:
		annot_map(left, e);
		right->prev = left;
		map_dec(e->st, left);
		expr->annot.type = TYPE_MAP_METHOD;
		break;
	default:
		get_annot(left, e);
		get_annot(right, e);
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
		annot_assign(n, e);
		break;
	case NODE_CALL:
		global_annot(n);
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
	n->annot.loc = LOC_STACK;
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

void loc_assign(node_t *node, ebpf_t *code) {
	switch (node->annot.type) {
	case TYPE_RSTR:
		assign_stack(node, code);
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

static int visit_list(node_t *head, ebpf_t *ctx) {
	node_t *elem, *next = head;

	for (elem = next; elem;) {
		next = elem->next;
		sema(elem, ctx);
		elem = next;
	}

	return 0;
}

void sema(node_t *node, ebpf_t *e) {
	
	get_annot(node, e);
	
	switch (node->type) {
	case NODE_PROBE:
		visit_list(node->probe.stmts, e);
		break;
	case NODE_CALL:
		visit_list(node->call.args, e);
		break;
	case NODE_IF:
		visit_list(node->iff.cond, e);
		visit_list(node->iff.then, e);
		break;
	default:
		break;
	}

	loc_assign(node, e);
}