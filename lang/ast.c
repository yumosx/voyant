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
    n->name = strdup(name);
    return n;
}

node_t* node_str_new(char* str) {
	node_t* n = node_new(NODE_STRING);
	n->name = strdup(str);
	return n;
}


node_t* node_int_new(char* name) {
    node_t* n = node_new(NODE_INT);
    n->name = name;
    return n;
}

void node_print_str(node_type_t type) {
    const char* node_type_str[] = {
        "TYE_SCRIPT",
        "TYPE_PROBE",
        "TYPE_EXPR",
        "TYPE_VAR",
        "TYPE_MAP",
        "TYPE_LET",
        "TYPE_ASSIGN",
        "TYPE_CALL",
        "TYPE_STRING",
        "TYPE_INT"
    };
    
    printf("%s\n", node_type_str[type]);
}


void probe_free(node_t* n) {
     

}
