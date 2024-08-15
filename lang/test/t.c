typedef struct sym {
    char* name;
    annot_t vannot;
    annot_t kannot;
}

void sym_annot(char* name, node_t* n) {
    sym_t* sym;

    sym = symtable_get(name, n);

    switch (n->type) {
    case NODE_VAR:
        sym->vannot = n->annot;
        break;
    case NODE_MAP:
        sym->annot = n->annot;
        sym->vannot = n->annot;
    default:
        break;
    } 
}

/*
void sym_annot(char* name, node_t* bind) {
    sym_t* sym;

    sym = symtable_get(e->st, name);

    switch (bind->type) {
    case NODE_VAR:
        sym->vannot = bind->annot;
        break;
    case NODE_MAP:
        sym->vannot = bind->annot;
        sym->kannot = bind->map.args->annot;
        break;
    default:
        break;
    }
}
*/

