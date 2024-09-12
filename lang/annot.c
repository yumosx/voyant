#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "annot.h"
#include "func.h"
#include "ut.h"

static void check_int(node_t* n) {
	node_type_t ty;

	ty = n->type;
	if (ty != NODE_INT) {
		verror("not an integer");
	}
}

static void annot_value(node_t* value) {
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

static void annot_map(node_t* map, ebpf_t* e) {
	node_t* arg;
	ssize_t ksize;

	arg = map->map.args;
	get_annot(arg, e);
	ksize = arg->annot.size;

	map->annot.type = TYPE_MAP;	
	map->annot.size = 8;
	map->annot.ksize = ksize;
}

static void annot_var(node_t* var, ebpf_t* e) {
	var->annot.type = TYPE_VAR;
	var->annot.size = 8;	
}

void annot_dec(node_t* n, ebpf_t* e) {
	node_t* var, *expr;
	
	var = n->dec.var;
	expr = n->dec.expr;	

	get_annot(expr, e);

	switch (var->type) {
	case NODE_VAR:
		annot_var(var, e);
		var->annot.size = expr->annot.size; 
		var_dec(e->st, var->name, expr);
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

void annot_assign(node_t* n, ebpf_t* e) {
	node_t* var, *expr;
	sym_t* sym;

	var = n->assign.lval;
	expr = n->assign.expr;

	get_annot(expr, e);
	symtable_ref(e->st, var);

	assert(expr->annot.type != var->annot.type);
}

void annot_expr(node_t* expr, ebpf_t* e) {
	int opcode;
	node_t* left, *right;

	left = expr->expr.left;
	right = expr->expr.right;

	get_annot(left, e);
	get_annot(right, e);

	check_int(left);
	check_int(right);

	expr->annot.type = TYPE_INT;
	expr->annot.size = 8;
}

void annot_rec(node_t* n, ebpf_t* e) {
	node_t* arg;
	ssize_t size = 0;

	_foreach(arg, n->rec.args) {
		get_annot(arg, e);
		size += arg->annot.size;
	}

	n->annot.size = size;
	n->annot.type = TYPE_REC;
}

void get_annot(node_t* n, ebpf_t* e) {
     switch(n->type) {
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

void assign_stack(node_t* n, ebpf_t* e) {
	n->annot.addr = ebpf_addr_get(n, e);
	n->annot.loc = LOC_STACK;
}

void assign_dec(node_t* dec, ebpf_t* e) {
	node_t* var, *expr;
	ssize_t addr;
	sym_t* sym;

	var = dec->dec.var;
	expr = dec->dec.expr;
	sym = symtable_get(e->st, var->name);
	addr = ebpf_addr_get(var, e);

	var->annot.addr = addr;
	sym->vannot.addr = addr;

	if (var->type == NODE_MAP) {
		node_t* args;
		args = var->map.args;
		addr = ebpf_addr_get(args, e);

		args->annot.addr = addr;	
		sym->map->kaddr = addr;
	}
}

void assign_rec(node_t* n, ebpf_t* e) {
	node_t* head;
	size_t offs;
	assign_stack(n, e);

	offs = n->annot.addr;
	
	_foreach(head, n->rec.args) {		
		head->annot.addr = offs;
		offs += head->annot.size;
	}
}

void loc_assign(node_t* n, ebpf_t* e) {
	switch (n->annot.type) {
	case TYPE_RSTR:
		assign_stack(n, e);
		break;
	case TYPE_DEC:
		assign_dec(n, e);
		break;
	case TYPE_REC:
		assign_rec(n, e);
		break;
	default:
		break;
	}
}

static int visit_list(node_t *head, pre_t* pre, post_t* post, ebpf_t* ctx) {
	node_t *elem, *next = head;
	
	for (elem = next; elem;) {
		next = elem->next;
		visit(elem, pre, post, ctx);
		elem = next;
	}

	return 0;
}

#define do_list(_head)	visit_list(_head, pre, post, e) 
#define do_walk(_node) 	visit(_node, pre, post, e)

void visit(node_t *n, pre_t pre, post_t post, ebpf_t *e) {
	if (pre) { pre(n, e);}
	
	switch (n->type) {
	case NODE_PROBE:
		do_list(n->probe.stmts);
		break;
	case NODE_CALL:
		do_list(n->call.args);
		break;
	case NODE_IF:
		do_walk(n->iff.cond);
		do_list(n->iff.then);
		break;
	default:
		break;
	}

	if (post) { post(n, e);}
}