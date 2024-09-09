#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "annot.h"
#include "func.h"
#include "ut.h"

void annot_int(node_t* n) {
	n->annot.type = ANNOT_INT;
	n->annot.size = sizeof(n->integer);
}

void annot_str(node_t* n) {
	n->annot.type = ANNOT_STR;
	n->annot.size = _ALIGNED(strlen(n->name) + 1);
}

void annot_var_dec(node_t* n, ebpf_t* e) {
	char* name;
	sym_t* sym;
	node_t* expr;

	expr = n->dec.expr;
	name = n->dec.var->name;
	n->annot.type = ANNOT_VAR_DEC;

	get_annot(expr, e);

	var_dec(e->st, name, expr);
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

void annot_expr(node_t* n, ebpf_t* e) {
	node_t* left;
	node_t* right;

	left = n->infix_expr.left;
	right = n->infix_expr.right;
	
	get_annot(left, e);
	get_annot(right, e);

	assert(left->annot.type == right->annot.type);
	n->annot = left->annot;
}

void annot_rec(node_t* n, ebpf_t* e) {
	node_t* arg;
	ssize_t size;

	_foreach(arg, n->rec.args) {
		get_annot(arg, e);
		size += arg->annot.size;
	}

	n->annot.size = size;
	n->annot.type = ANNOT_REC;
}

void get_annot(node_t* n, ebpf_t* e) {
     switch(n->type) {
        case NODE_INT:
			annot_int(n);
			break;
        case NODE_STRING:
			annot_str(n);
			break;
		case NODE_EXPR:
			annot_expr(n, e);
			break;
		case NODE_DEC:
			annot_var_dec(n, e);
			break;
		case NODE_VAR:
			symtable_ref(e->st, n);
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
	n->annot.addr = stack_addr_get(n, e);
	n->annot.loc = LOC_STACK;
}

void assign_var_stack(node_t* n, ebpf_t* e) {
	node_t* var, *expr;
	sym_t* sym;

	var = n->dec.var;
	expr = n->dec.expr;

	sym = symtable_get(e->st, var->name);
	sym->vannot.addr = stack_addr_get(expr, e); 
	
	var->annot.addr = sym->vannot.addr;
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
	
	n->annot.loc = LOC_STACK;
}

void loc_assign(node_t* n, ebpf_t* e) {
	switch (n->annot.type) {
	case ANNOT_STR:
		assign_stack(n, e);
		break;
	case ANNOT_RSTR:
		assign_stack(n, e);
		break;
	case ANNOT_VAR_DEC:
		assign_var_stack(n, e);
		break;
	case ANNOT_REC:
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
		do_list(n->iff.cond);
		do_list(n->iff.then);
		break;
	default:
		break;
	}

	if (post) { post(n, e);}
}