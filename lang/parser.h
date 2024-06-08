#ifndef PARSER_H
#define PARSER_H


#include "lexer.h"
#include "ast.h"

typedef enum {
    LOWEST = 1,
    ASSIGN,
    EQUALS,          //==
    LESSGREATERA,    //> or <
    SUM,            //+
    PRODUCT,        //*
    PREFIX,         //!1
    CALL,
    INDEX,
} seq_t;


typedef struct parser_t {
    lexer_t* lexer;
    token_t* this_tok;
    token_t* next_tok;
} parser_t;

void p_next_tok(parser_t* p); 
parser_t* parser_init(lexer_t* l); 
node_t* parse_expr(parser_t* p, seq_t s); 
node_t* parse_probe(parser_t* p); 

#endif
