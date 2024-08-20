#include <stdio.h>
#include <string.h>

#include "ast.h"
#include "symtable.h"
#include "buffer.h"
#include "dsl.h"
#include "arch.h"
#include "ut.h"
#include "func.h"
#include "syscall.h"

ssize_t stack_addr_get(node_t* n, ebpf_t* e) {
	if (n->type == NODE_MAP) {
		e->st->sp -= n->annot.keysize;
	}
	
	e->st->sp -= n->annot.size;
	return e->st->sp;
}

reg_t* reg_get(ebpf_t* e) {
	reg_t* r;
	
	for (r = &e->reg[BPF_REG_8]; r >= &e->reg[BPF_REG_6]; r--) {
		if (r->type == BPF_REG_EMPTY) {
			return r;
		}
	}
}

void reg_bind(node_t* n, ebpf_t* e, reg_t* r) {
	if (n->type == NODE_VAR) {
		sym_t* sym;
		sym = symtable_get(e->st, n->name);
		sym->reg = r;
		r->type = BPF_REG_SYM;
		r->sym = sym;
	} else {
		r->type = BPF_REG_NODE;
		r->node = n;
	}
}

reg_t* reg_bind_find(node_t* n, ebpf_t* e) {
	reg_t* reg;
	int type;
	sym_t* sym;

	type = BPF_REG_NODE;

	if (n->type == NODE_VAR) {
		sym = symtable_get(e->st, n->name);
		type = BPF_REG_SYM;
	}

	for (reg = &e->reg[BPF_REG_8]; reg >= &e->reg[BPF_REG_6]; reg--) {
		if (reg->type == BPF_REG_NODE && reg->node == n) {
			return reg;
		}
		if (reg->type == BPF_REG_SYM && reg->sym == sym) {
			return reg;
		}
	}
}

static int type_check(node_t* p) {
	switch (p->type) {
	case NODE_ASSIGN:
		break;
	case NODE_INFIX_EXPR:
		break;	
	default:
		break;
	}

}

void annot_int(node_t* n, ebpf_t* e) {
	n->annot.type = ANNOT_INT;
	n->annot.size = sizeof(n->integer);
}

void annot_str(node_t* n, ebpf_t* e) {
	n->annot.type = ANNOT_STR;
	n->annot.size = _ALIGNED(strlen(n->name) + 1);
}

void annot_sym(node_t* n, ebpf_t* e) {
	sym_t* sym;

	sym = symtable_get(e->st, n->name);
	
	if (!sym) {
		symtable_add(e->st, n);
	}
	
	n->annot = sym->vannot;
}

void annot_assign(node_t* n, ebpf_t* e) {
	node_t* val, *expr;

	val = n->assign.lval;
	expr = n->assign.expr;

	annot_sym(val, e);
	get_annot(expr, e);

	val->annot = expr->annot;
}

void annot_sym_assign(node_t* n, ebpf_t* e) {
	sym_t* sym;
	node_t* var, *expr;

	var = n->assign.lval, expr = n->assign.expr;
	get_annot(expr, e);

	var->annot = expr->annot;
	symtable_add(e->st, n->assign.lval);
	n->annot.type = ANNOT_SYM_ASSIGN;
}

void annot_map(node_t* n, ebpf_t* e) {
	ssize_t ksize, vsize;
	int fd;

	get_annot(n->map.args, e);
	ksize = n->map.args->annot.size;
	n->annot.keysize = ksize;
	n->annot.size = 8;

	fd = bpf_map_create(BPF_MAP_TYPE_HASH, ksize, 8, 1024);
	n->annot.mapid = fd;
	
	symtable_add(e->st, n);
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

void annot_call(node_t* n, ebpf_t* e) {
	int err;
	
	err = global_annot(n);
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
            annot_int(n, e);
			break;
        case NODE_STRING:
			annot_str(n, e);
			break;
        case NODE_CALL:
            annot_call(n, e);
			break;
		case NODE_INFIX_EXPR:
			annot_binop(n, e);
			break;
		case NODE_MAP:
		case NODE_VAR:
			annot_sym(n, e);
			break;
		case NODE_ASSIGN:
			annot_sym_assign(n, e);
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

void assign_sym_reg(node_t* n, ebpf_t* e) {
	reg_t* reg;

	reg = reg_get(e);
	reg_bind(n->assign.lval, e, reg);

	n->annot.loc = LOC_REG;
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
	sym->addr = n->annot.addr;

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
	case ANNOT_SYM_ASSIGN:
		assign_sym_reg(n, e);	
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


ebpf_t* ebpf_new() {
    ebpf_t* e = vcalloc(1, sizeof(*e));
    e->st = symtable_new();     
	e->ip = e->prog;
    e->evp = vcalloc(1, sizeof(*e->evp));
	
	for (int i = BPF_REG_0; i < __MAX_BPF_REG; i++) {
		*(int*)(&e->reg[i].reg) = i;
		*(int*)(&e->reg[i].type) = BPF_REG_EMPTY;
	}
		
	return e;
}

static int _node_walk_list(node_t *head,
			 void (*pre) (node_t *n, ebpf_t *ctx),
			 void (*post)(node_t *n, ebpf_t *ctx), ebpf_t *ctx)
{
	node_t *elem, *next = head;
	int err = 0;
	
	for (elem = next; !err && elem;) {
		next = elem->next;
		node_pre_traversal(elem, pre, post, ctx);
		elem = next;
	}

	return err;
}

#define do_list(_head)	_node_walk_list(_head, pre, post, e) 
#define do_walk(_node) 	node_iter(_node, pre, post, e)

void node_pre_traversal(node_t *n, 
	void (*pre) (node_t *n, ebpf_t *e), 
	void (*post)(node_t *n, ebpf_t *e), ebpf_t *e) {

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