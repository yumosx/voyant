#ifndef AST_H
#define AST_H



typedef struct node_t{
    node_type_t type;
    node_t* prev, *next;
    node_t* parent;
    char* name;

    union {
        probe_t probe;
        infix_t infix_expr;
        prefix_t prefix_expr;
        call_t call;
        map_t map;
        assign_t assign;
        size_t integer;
    };

    annot_t annot;
} node_t;

#endif
