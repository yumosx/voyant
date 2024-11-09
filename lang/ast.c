#include <stdio.h>
#include <stdlib.h>

#include "ut.h"
#include "ast.h"

node_t *node_new(node_type t) {
    node_t *n = vmalloc(sizeof(*n));

    n->type = t;
    return n;
}

node_t *node_var_new(char *name) {
    node_t *n = node_new(NODE_VAR);

    n->name = name;
    return n;
}

node_t *node_str_new(char *str) {
    node_t *n = node_new(NODE_STR);
    n->name = str;
    return n;
}

node_t *node_int_new(size_t integer) {
    node_t *n = node_new(NODE_INT);
    n->integer = integer;
    return n;
}

node_t *node_expr_new(int opcode, node_t *left, node_t *right) {
    node_t *n = node_new(NODE_EXPR);

    n->expr.opcode = opcode;
    n->expr.left = left;
    n->expr.right = right;

    return n;
}

node_t *node_assign_new(node_t *left, node_t *expr) {
    node_t *n = node_new(NODE_ASSIGN);

    n->assign.op = OP_MOV;
    n->assign.lval = left;
    n->assign.expr = expr;

    return n;
}

node_t *node_rec_new(node_t *args) {
    node_t *n = node_new(NODE_REC);
    n->rec.args = args;
    return n;
}

node_t *node_if_new(node_t *cond, node_t *then, node_t *els) {
    node_t *c, *n = node_new(NODE_IF);

    n->iff.cond = cond;
    n->iff.then = then;
    n->iff.els = els;
    
    return n;
}

node_t *node_unroll_new(size_t count, node_t *stmts) {
    node_t *n = node_new(NODE_UNROLL);

    n->unroll.count = count;
    n->unroll.stmts = stmts;

    return n;
}

node_t* node_cast_new(char* name, char* value) {
    node_t* n = node_new(NODE_CAST);
    n->cast.name = name;
    n->cast.value = value;
    return n;
}

node_t *node_dec_new(node_t *var, node_t *expr) {
    node_t *n = node_new(NODE_DEC);

    n->dec.var = var;
    n->dec.expr = expr;

    return n;
}

node_t *node_probe_new(char *name, node_t *stmts) {
    node_t *n = node_new(NODE_PROBE);

    n->probe.name = name;
    n->probe.stmts = stmts;

    return n;
}

node_t *node_kprobe_new(char *name, node_t *stmts) {
    node_t *n = node_new(NODE_KPROBE);

    n->probe.name = name;
    n->probe.stmts = stmts;

    return n;
}

node_t* node_test_new(char* name, node_t* stmts) {
    node_t* n = node_new(NODE_TEST);

    n->probe.name = name;
    n->probe.stmts = stmts;

    return n;
}

static int do_list(node_t *head) {
	node_t *elem, *next = head;

	for (elem = next; elem;) {
		next = elem->next;
		free_node(elem);
		elem = next;
	}

	return 0;
}


void free_node(node_t *node) {
    switch (node->type) {
    case NODE_PROBE:
    case NODE_KPROBE:
        free(node->probe.name);
        do_list(node->probe.stmts);
        break;
    case NODE_CALL:
        free(node->name);
        if (node->call.args)
            do_list(node->call.args);
        break;
    case NODE_DEC:
        free(node->dec.var);
        free(node->dec.expr);
        break;
    case NODE_REC:
        do_list(node->rec.args);
        break;
    case NODE_STR:
        free(node->name);
        break;
    default:
        break;
    }
}