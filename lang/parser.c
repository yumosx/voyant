#include "parser.h"

void p_next_tok(parser_t* p) {    
    p->this_tok = p->next_tok;
    p->next_tok = lexer_next_token(p->lexer);
}

parser_t* parser_init(lexer_t* l) {
    parser_t* p = malloc(sizeof(*p));

    if (p == NULL) {
        err(EXIT_FAILURE, "parser malloc failed");
    }
    
    p->lexer = l;
    p->this_tok = NULL;
    p->next_tok = NULL;

    p_next_tok(p);
    p_next_tok(p);

    return p;
}

int this_tok_is(parser_t* p, token_type type) {
    return p->this_tok->type == type;
}

int next_tok_is(parser_t* p, token_type type) {
    return p->next_tok->type == type;
}

int expect_peek(parser_t* p, token_type t) {
    if (next_tok_is(p, t)) {
        p_next_tok(p);
        return 1;
    } else {
        return 0;
    }
}


