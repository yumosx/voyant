#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "annot.h"
#include "func.h"
#include "ut.h"

#define STRING_SIZE 64

void annot_int(node_t* integer) {
	integer->annot.type = TYPE_INT;
	integer->annot.size = sizeof(integer->integer);	
}

void annot_str(node_t* string) {
    size_t size;

    size = strlen(string->name) + 1;
    if (size > STRING_SIZE) {
        verror("string is to long (over %d bytes): %s", STRING_SIZE, string->name);
    }
    string->annot.type = TYPE_STR;
    string->annot.size = _ALIGNED(size);
}

static int annot_value(node_t *value) {
	int err = 0;
	
	switch (value->type) {
	case NODE_INT:
		annot_int(value);
		break;
	case NODE_STR:
		annot_str(value);
		break;
	case NODE_CALL:
		err = global_annot(value);
		break;
	default:
		break;
	}

	return err;
}

static void annot_map_args(node_t *map, ebpf_t *e) {
	node_t *arg;
	ssize_t ksize;

	arg = map->map.args;
	get_annot(arg, e);
	ksize = arg->annot.size;

	map->annot.type = TYPE_INT;
	map->annot.ksize = ksize;
	map->annot.size = 8;
}

int annot_map_method(node_t* expr, ebpf_t* ctx) {
	int err = 0;
	node_t* left, *right;

	left = expr->expr.left;
	right = expr->expr.right;

	annot_map_args(left, ctx);

	right->parent = left;
	map_dec(ctx->st, left, NULL);
	expr->annot.type = TYPE_MAP_METHOD;

	return err;
}

static int annot_dec(node_t *n, ebpf_t *e) {
	node_t *var, *expr;
	int err = 0;
	
	var = n->dec.var;
	expr = n->dec.expr;

	get_annot(expr, e);

	switch (var->type) {
	case NODE_VAR:
		var->annot.type = expr->annot.type;
		var->annot.size = expr->annot.size;
		var_dec(e->st, var, expr);
		break;
	case NODE_MAP:
		annot_map_args(var, e);
		var->annot.type = expr->annot.type;
		var->annot.size = expr->annot.size;
		map_dec(e->st, var, expr);
		break;
	default:
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

	switch (data->annot.type){
	case TYPE_INT:
		expr->annot.size = 8;
		expr->annot.type = TYPE_INT;
		break;
	case TYPE_STR:
		expr->annot.size = 64;
		expr->annot.type = TYPE_STR;
		break;
	default:
		break;
	}
}

static inline int is_arg(const char* name) {
	return (strstr(name, "arg") == name) 
		&& (strlen(name) == 4)
		&& (name[3] >= '0' && name[3] <= 9);
}

void annot_cast(node_t* expr, ebpf_t* ctx) {
	size_t size;
	char* arg, name;
	int num;

	arg = expr->cast.value;
	num = arg[3];

	expr->annot.size = 0;
	expr->annot.type = TYPE_CAST;
	expr->annot.offs = num - '0';
}

void annot_struct_filed(node_t* expr, ebpf_t* ctx) {
	sym_t* sym;
	int offs;
	char* sname, *filed;

	sym = symtable_get(ctx->st, expr->expr.left->name);
	sname = sym->cast;
	filed = expr->expr.right->name;

	offs = btf_get_field_off(sname, filed);

	expr->annot.offs = offs;
	expr->annot.size = 8;
	expr->annot.type = TYPE_INT;
}

void annot_accses(node_t* expr, ebpf_t* ctx) {
	sym_t* sym;
	
	sym = symtable_get(ctx->st, expr->expr.left->name);
	if (!sym) {
		annot_probe_args(expr, ctx);
		return;
	}
	
	annot_struct_filed(expr, ctx);
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
		annot_accses(expr, ctx);
		break;
	default:
		get_annot(left, ctx);
		get_annot(right, ctx);
		expr->annot.type = TYPE_INT;
		expr->annot.size = 8;
		break;
	}
}

void annot_rec(node_t *n, ebpf_t *code) {
	node_t *arg;
	ssize_t size = 0;

	_foreach(arg, n->rec.args) {
		get_annot(arg, code);
		
		size += arg->annot.size;
	}

	n->annot.size = size;
	n->annot.type = TYPE_REC;
}

void annot_probe(node_t* probe, ebpf_t* ctx) {
	int id;
	
	switch (probe->type) {
	case NODE_KPROBE:
		id = bpf_get_kprobe_id(probe->probe.name);
		break;
	case NODE_PROBE:
		ctx->name = probe->probe.name;
		id = bpf_get_probe_id(ctx->name);
		break;
	default:
		break;
	}

	probe->probe.traceid = id;
}

void sym_ref_assign(node_t* node, ebpf_t* code) {
	node_t* arg;
	arg = node->map.args;

	symtable_ref(code->st, node);
	arg->annot.addr = ebpf_addr_get(node, code);
}


void get_annot(node_t *node, ebpf_t *code) {
	switch (node->type) {
	case NODE_KPROBE:
	case NODE_PROBE:
		annot_probe(node, code);
		break;
	case NODE_CALL:
	case NODE_INT:
	case NODE_STR:
		annot_value(node);
		break;
	case NODE_VAR:
		symtable_ref(code->st, node);
		break;
	case NODE_MAP:
		sym_ref_assign(node, code);
		break;
	case NODE_EXPR:
		annot_expr(node, code);
		break;
	case NODE_DEC:
		annot_dec(node, code);
		break;
	case NODE_CAST:
		annot_cast(node, code);
		break;
	case NODE_REC:
		annot_rec(node, code);
		break;
	default:
		break;
	}
}

void assign_stack(node_t* node, ebpf_t *code) {
	node->annot.addr = ebpf_addr_get(node, code);
}

void assign_data(node_t* node, ssize_t addr) {
	switch (node->annot.type) {
	case TYPE_STR:
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

	if (expr->type == NODE_CAST) {
		return;
	}

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

void assign_rec(node_t *node, ebpf_t *code) {
	node_t *head;
	size_t offs;
	assign_stack(node, code);

	offs = node->annot.addr;

	_foreach(head, node->rec.args) {
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

void assign_expr(node_t* node, ebpf_t* code) {
	int op = node->expr.opcode;
	node_t* left = node->expr.left;
	node_t* right = node->expr.right;

	switch (op) {
	case OP_PIPE:
		assign_method(node, code);
		return;
	default:
		break;
	}

	if (left->type == NODE_MAP) {
		left->annot.addr = ebpf_addr_get(left, code);
	}

	if (right->type == NODE_MAP) {
		right->annot.addr = ebpf_addr_get(right, code);
	}
}

void loc_assign(node_t* node, ebpf_t* code) {
	switch (node->type) {
	case NODE_DEC:
		assign_dec(node, code);
		break;
	case NODE_REC:
		assign_rec(node, code);
		break;
	case NODE_EXPR:
		assign_expr(node, code);
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
	case NODE_KPROBE:
	case NODE_PROBE:
		do_list(node->probe.stmts, ctx);
		break;
	case NODE_TEST:
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