#include <stdio.h>
#include <stdlib.h>

#include "ast.h"

node_t* node_new(node_type_t t) {
    node_t* n = malloc(sizeof(*n));

    if (n == NULL) {
       err(EXIT_FAILURE, "Failed to allocate memory for a new node of type %d", t);
    }

    n->type = t;
    return n;
}

/*
note we use the strdup to copy the string
beacuse we release the lexer token
*/
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

void probe_free(node_t* n) {
}
