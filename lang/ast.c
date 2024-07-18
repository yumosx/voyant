#include <stdio.h>
#include <stdlib.h>

#include "ut.h"
#include "ast.h"

node_t* node_new(node_type_t t) {
    node_t* n = checked_malloc(sizeof(*n));
    n->type = t;
    return n;
}

node_t* node_new_var(char* name) {
    node_t* n = node_new(NODE_VAR);
    n->name = name;
    return n;
}

node_t* node_str_new(char* str) {
	node_t* n = node_new(NODE_STRING);
	n->name = str;
	return n;
}

node_t* node_int_new(size_t integer) {
    node_t* n = node_new(NODE_INT);
	n->integer = integer;
    return n;
}

node_t* node_expr_new(int opcode, node_t* left, node_t* right) {
	node_t* n = node_new(NODE_INFIX_EXPR);
	n->infix_expr.opcode = opcode;
	n->infix_expr.left = left;
	n->infix_expr.right = right;

	return n;
}

node_t* node_assign_new(node_t* left, node_t* expr) {
	node_t* n = node_new(NODE_ASSIGN);
	n->assign.op = OP_MOV;
	n->assign.lval = left;
	n->assign.expr = expr;
}

node_t* node_probe_new(char* name, node_t* stmts) {
	node_t* n = node_new(NODE_PROBE);
	n->probe.name = name;
	n->probe.stmts = stmts;
	return n;
}

void node_print_str(node_type_t type) {
    const char* node_type_str[] = {
        "TYE_SCRIPT",
        "TYPE_PROBE",
        "TYPE_EXPR",
        "TYPE_VAR",
        "TYPE_MAP",
        "TYPE_ASSIGN",
        "TYPE_CALL",
        "TYPE_STRING",
        "TYPE_INT"
    };
    
    printf("%s\n", node_type_str[type]);
}

void probe_free(node_t* n) {
    node_t* head;
	free(n->probe.name);
}
