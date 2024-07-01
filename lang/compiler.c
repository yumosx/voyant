#include <stdio.h>



inline void annot_call(node_t* node) {
    if (!strcmp(node->name, "comm")) {
        node->annot.type = NODE_STR;
        node->annot.size = 16;
    } else {
        node->annot.type = NODE_INT;
        node->annot.size = 8;
    }
}


void annot_type(node_t* node) {
    switch (node->type) {
    case NODE_INT:
         node->annot.type = NODE_INT;
         node->annot.size = 8;
         break;   
    case NODE_STRING:
         node->annot.type = NODE_STRING;
         node->annot.size = _ALIGNED(strlen(node->name) + 1);          
         node->annot.addr = symtable_reverse(node, node->annot.size);
         break;
    case NODE_CALL:
         annot_call(node);
         break;
    case NODE_MAP:
        break;
    }
}
