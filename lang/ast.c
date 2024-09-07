#include <stdio.h>
#include <stdlib.h>

#include "ut.h"
#include "ast.h"

node_t* node_new(node_type_t t) {
    node_t* n = vmalloc(sizeof(*n));
    n->type = t;
    
    return n;
}

node_t* node_var_new(char* name) {
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
	node_t* n = node_new(NODE_EXPR);
	
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
    
    return n;
}

node_t* node_rec_new(node_t* args) {
	node_t* n = node_new(NODE_REC);
	n->rec.args = args; 
	return n;
}

node_t* node_if_new(node_t* cond, node_t* then, node_t* els) {
    node_t* c, *n = node_new(NODE_IF);

    n->iff.cond = cond;
    n->iff.then = then;
    n->iff.els = els;

    return n;
}

node_t* node_unroll_new(size_t count, node_t* stmts) {
    node_t* c, *n = node_new(NODE_UNROLL);

    n->unroll.count = count;
    n->unroll.stmts = stmts;

    return n;
}

node_t* node_dec_new(node_t* var, node_t* expr) {
    node_t* n = node_new(NODE_DEC);
    
    n->dec.var = var;
    n->dec.expr = expr;
    
    return n;
}

node_t* node_probe_new(char* name, node_t* stmts) {
	node_t* n = node_new(NODE_PROBE);
	
    n->probe.name = name;
	n->probe.stmts = stmts;
	return n;
}

void node_probe_free(node_t* n) {
    node_t* head;

    _foreach(head, n->probe.stmts) {
        if (head->name) {
            free(head->name);
        }
    }
}

void node_stmts_free(node_t* n) {
    switch (n->type) {
    case NODE_STRING:
        free(n->name);
        break;
    case NODE_INT:
        break;
    case NODE_DEC:
        break;
    default:
        break;
    }
}