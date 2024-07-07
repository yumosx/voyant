#include <stdio.h>

#include "ast.h"
#include "symtable.h"
#include "dsl.h"

void annot_call(node_t* node, ebpf_t* e) {
	if (!strcmp(node->name, "comm")) {
		node->annot.type = NODE_STRING;
		node->annot.size = 16;
		node->annot.addr = symtable_reverse(e->st, node->annot.size);
		node->annot.loc = LOC_STACK;
	} else {
		node->annot.type = NODE_INT;
		node->annot.size = 16;
		node->annot.loc = LOC_STACK;
	}
}

void annot_var(node_t* n, ebpf_t* e) {
	node_t* lval = n->assign.lval, *expr = n->assign.expr;

	if (expr->type == NODE_VAR) {
		symtable_transfer(e->st, expr);
	} else {
		get_annot(n->assign.expr, e);
	}

	lval->annot.size = expr->annot.size;
	lval->annot.type = expr->annot.type;

	if (lval->type == NODE_MAP) {
		node_t* head, *args = lval->map.args;
		ssize_t ksize = 0;
	    for (head = args; head != NULL; head = head->next) {
			get_annot(head, e);
			ksize += head->annot.size;
		}
		lval->annot.keysize = ksize;
		lval->annot.addr = symtable_reverse(e->st, expr->annot.size + ksize); 
	}
	symtable_add(e->st, lval);
}

void annot(node_t* n, ebpf_t* e) {
	switch ( n->type ) {
		case NODE_INT:
			n->annot.type = NODE_INT;
			n->annot.size = sizeof(n->integer);
			break;
		case NODE_STRING:
			n->annot.type = NODE_STRING;
			n->annot.size = _ALIGNED(strlen(n->name) + 1);
			n->annot.addr = symtable_reverse(e->st, n->annot.size);
			n->annot.loc = LOC_STACK;
			break;
		case NODE_CALL:
			annot_call(n, e);
			break;
		case NODE_ASSIGN:
			annot_var(n, e);		    	
			break;
	}	
}
