#include <stdio.h>

#include "ast.h"
#include "symtable.h"
#include "dsl.h"


void annot_map(node_t* n, ebpf_t* e) {
   	node_t* lval = n->assign.lval, *expr = n->assign.expr;

    if (expr->type == NODE_VAR) {
        symtable_transfer(e->st, expr);  
    } else {
        get_annot(expr, e);
    }
   
   lval->annot.type = expr->annot.type;
   lval->annot.size = expr->annot.size;
   
   if (lval->type == NODE_MAP) {
        node_t* head, *args = lval->map.args;
        ssize_t ksize = 0; 
        
        for (head = args; head != NULL; head = head->next) {
            get_annot(head, e);
            ksize += head->annot.size;
        }

        lval->annot.keysize = ksize;
		lval->annot.addr = symtable_reserve(e->st, ksize + lval->annot.size);

        int fd = bpf_map_create(BPF_MAP_TYPE_HASH, lval->annot.keysize, lval->annot.size, 1024);
        lval->annot.mapid = fd;
   }
    
    symtable_add(e->st, n->assign.lval);     
}


void comm_annot(node_t* n, ebpf_t* e) {
    n->annot.type = NODE_STRING;
    n->annot.size = _ALIGNED(16);
    n->annot.addr = symtable_reserve(e->st, n->annot.size);
    n->annot.loc = LOC_STACK;
}


void call_annot(node_t* n, ebpf_t* e) {
	if (!strcmp("comm", n->name)) {
       comm_annot(n, e);
    } else {
	  n->annot.type = NODE_INT;
	  n->annot.size = 8;
	  n->annot.loc = LOC_REG;
    }
}

void get_annot(node_t* n, ebpf_t* e) {
     switch(n->type) {
        case NODE_INT:
            n->annot.type = NODE_INT;
            n->annot.size = sizeof(n->integer);
            break;
        case NODE_STRING:
            n->annot.type = NODE_STRING;
            n->annot.size = _ALIGNED(strlen(n->name) + 1);
            n->annot.addr = symtable_reserve(e->st, n->annot.size);
            n->annot.loc  = LOC_STACK; 
            break;
        case NODE_CALL:
            call_annot(n, e);
			break;
       case NODE_ASSIGN:
            annot_map(n, e);
            break;
        default:
            break;
    }
}
