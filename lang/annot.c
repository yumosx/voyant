#include <stdio.h>
#include <string.h>

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

void annot_map(node_t* n, ebpf_t* e) {
	node_t* arg;
	ssize_t ksize, vsize;
	int fd;

	arg = n->map.args;
	get_annot(arg, e);
	ksize = n->map.args->annot.size;
	fd = bpf_map_create(BPF_MAP_TYPE_HASH, ksize, 8, 1024);
	
	n->annot.mapid = fd;
	n->annot.keysize = ksize;
	n->annot.size = 8;
	n->annot.type = ANNOT_INT;
	n->annot.ktype = arg->annot.type;

	symtable_add(e->st, n->name);
	sym_annot(e->st, SYM_MAP, n);
}


void annot_binop(node_t* n, ebpf_t* e) {
	node_t* left, *right;
	int op;

	op = n->infix_expr.opcode;
	left = n->infix_expr.left;
	right = n->infix_expr.right;

	switch (op) {
	case OP_PIPE:
		annot_map(left, e);
		right->prev = left;
		n->annot.type = ANNOT_MAP_METHOD;
		break;
	default:
		break;
	}
}

void annot_dec(node_t* n, ebpf_t* e) {
	char* name;
	sym_t* sym;
	node_t* expr;

	expr = n->dec.expr;
	name = n->dec.var->name;
	n->annot.type = ANNOT_VAR_DEC;

	get_annot(expr, e);
	sym = symtable_add(e->st, name);		
	sym->vannot = expr->annot;
}

void annot_assign(node_t* n, ebpf_t* e) {
	node_t* var, *expr;
	sym_t* sym;

	var = n->assign.lval;
	expr = n->assign.expr;

	get_annot(expr, e);
	symtable_ref(e->st, var);

	if (expr->annot.type != var->annot.type) {
		verror("left value and right value not match");
	}
}

void annot_rec(node_t* n, ebpf_t* e) {
	node_t* arg;
	ssize_t size = 0;
	
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
        case NODE_CALL:
			global_annot(n);
			break;
		case NODE_INFIX_EXPR:
			annot_binop(n, e);
			break;
		case NODE_DEC:
			annot_dec(n, e);
			break;
		case NODE_VAR:
			symtable_ref(e->st, n);
			break;
		case NODE_ASSIGN:
			annot_assign(n, e);
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

void assign_var_reg(node_t* n, ebpf_t* e) {
	node_t* var;
	sym_t* sym;
	reg_t* reg;

	var = n->dec.var;
	sym = symtable_get(e->st, var->name);

	switch (sym->vannot.type) {
	case ANNOT_STR:	
		break;
	case ANNOT_INT:
		reg = reg_get(e);
		reg_bind(var, e, reg);
		n->annot.loc = LOC_REG;
		break;
	default:
		break;
	}
}

void assign_map(node_t* n, ebpf_t* e) {
	sym_t* sym;
	node_t* key;
	size_t kaddr;

	assign_stack(n, e);
	key = n->map.args;
	kaddr = n->annot.addr;
	key->annot.addr = kaddr;

	sym = symtable_get(e->st, n->name);
	sym->vannot.addr = n->annot.addr;

	n->annot.loc = LOC_STACK;
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
	case ANNOT_VAR_DEC:
		assign_var_reg(n, e);
		break;
	case ANNOT_MAP_METHOD:
		assign_map(n->infix_expr.left, e);
		break;
	case ANNOT_RSTR:
		assign_stack(n, e);
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
	int err = 0;
	
	for (elem = next; !err && elem;) {
		next = elem->next;
		visit(elem, pre, post, ctx);
		elem = next;
	}

	return err;
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
	default:
		break;
	}

	if (post) { post(n, e);}
}