#include <stdio.h>
#include <string.h>

#include "ast.h"
#include "symtable.h"
#include "buffer.h"
#include "dsl.h"
#include "ut.h"
#include "syscall.h"


ssize_t get_stack_addr(node_t* n, ebpf_t* e) {
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

static void printf_spec(const char* spec, const char* term, void* data, node_t* arg) {
	int64_t num;
	size_t fmt_len;
	char* fmt;

	memcpy(&num, data, sizeof(num));
	fmt_len = term - spec + 1;
	fmt = strndup(spec, fmt_len);
	
	switch(*term) {
	case 's':
		printf(fmt, (char*)data);
		printf("\n");
		break;
	case 'd':
		printf(fmt, (int)num);
		printf("\n");
		break;
	}

	free(fmt);
}

static int event_output(event_t* ev, void* _call) {
	node_t* arg, *call = _call;
	char* fmt, *spec;
	void* data = ev->data;
	
	arg = call->call.args->next->rec.args->next; 
	for (fmt = call->call.args->name; *fmt; fmt++) {
		if (*fmt == '%' && arg) {
			spec = fmt;
			fmt = strpbrk(spec, "scd");
			if (!fmt) 
				break;
			printf_spec(spec, fmt, data, arg);
			
			data += arg->annot.size;
			arg = arg->next;
		} else {
			fputc(*fmt, stdout);
		}
	}
	return 0;
}

void annot_int(node_t* n, ebpf_t* e) {
	n->annot.type = ANNOT_INT;
	n->annot.size = sizeof(n->integer);
}

void annot_str(node_t* n, ebpf_t* e) {
	n->annot.type = ANNOT_STR;
	n->annot.size = _ALIGNED(strlen(n->name) + 1);
}

void annot_func_rint(node_t* n, ebpf_t* e) {
	n->annot.type = ANNOT_RINT;
	n->annot.size = 8;
}

void annot_func_rstr(node_t* n, ebpf_t* e) {
	n->annot.type = ANNOT_RSTR;
	n->annot.size = _ALIGNED(16);
}

void annot_sym(node_t* n, ebpf_t* e) {
	sym_transfer(e->st, n);	
}

void annot_map_assign(node_t* p, node_t* n, ebpf_t* e) {
	ssize_t ksize, vsize;
	int fd;

	get_annot(n->map.args, e);
	ksize = n->map.args->annot.size;

	n->annot.keysize = ksize;
	
	fd = bpf_map_create(BPF_MAP_TYPE_HASH, ksize, n->annot.size, 1024);
	n->annot.mapid = fd;
	p->annot.type = ANNOT_MAP_ASSIGN;
	symtable_add(e->st, n);
}

void annot_sym_assign(node_t* n, ebpf_t* e) {
	sym_t* sym;
	node_t* var, *expr;

	var = n->assign.lval, expr = n->assign.expr;
	get_annot(expr, e);


	var->annot = expr->annot;
	
	if (var->type == NODE_MAP) {
		annot_map_assign(n, var, e);
		return;
	}

	symtable_add(e->st, n->assign.lval);
	n->annot.type = ANNOT_SYM_ASSIGN;
}

void annot_call(node_t* n, ebpf_t* e) {
	if (!strcmp("comm", n->name)) {
		annot_func_rstr(n, e);
	} else if (!strcmp("out", n->name)) { 
		annot_perf_output(n, e);
	} else {
		annot_func_rint(n, e);
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
            annot_int(n, e);
			break;
        case NODE_STRING:
			annot_str(n, e);
			break;
        case NODE_CALL:
            annot_call(n, e);
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
	n->annot.addr = get_stack_addr(n, e);
	n->annot.loc = LOC_STACK;
}

void assign_sym_reg(node_t* n, ebpf_t* e) {
	reg_t* reg;

	reg = reg_get(e);
	reg_bind(n->assign.lval, e, reg);

	n->annot.loc = LOC_REG;
}

void assign_map_stack(node_t* n, ebpf_t* e) {
	sym_t* sym;

	assign_stack(n->assign.lval, e);
	sym = symtable_get(e->st, n->assign.lval->name);
	sym->addr = n->assign.lval->annot.addr;
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
	case ANNOT_MAP_ASSIGN:
		assign_map_stack(n, e);
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

void annot_perf_output(node_t* call, ebpf_t* e) {
	evhandler_t* evh;
	node_t* meta, *head, *varg, *rec;
	size_t size; 
	ssize_t addr;

	varg = call->call.args;
	if (!varg) {
		_errmsg("should has a string fromat");
		return -1;
	}
    
	evh = checked_calloc(1, sizeof(*evh));
    evh->priv = call;
	evh->handle = event_output;
	
	evhandler_register(evh);	
	
	meta = node_int_new(evh->type);
	meta->annot.type = ANNOT_INT;
	meta->annot.size = 8;
	meta->next = varg->next;
	
	rec = node_rec_new(meta);
	varg->next = rec;
}

ebpf_t* ebpf_new() {
    ebpf_t* e = checked_calloc(1, sizeof(*e));
    e->st = symtable_new();     
	e->ip = e->prog;
    e->evp = checked_calloc(1, sizeof(*e->evp));
	
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