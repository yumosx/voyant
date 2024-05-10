#ifndef LEXER_H
#define LEXER_H

#include <stddef.h>

#define get_token_name(tok) tok_type_str[tok->type]

extern const char* tok_type_str[];

typedef enum token_type{
    TOKEN_IDENT,
    TOKEN_INT,
    TOKEN_STRING,
    TOKEN_ILLEGAL,
    TOKEN_PROBE,
    TOKEN_FILTER,
    TOKEN_SLASH,
    TOKEN_COLON,
    TOKEN_COMMA,
    TOKEN_LEFT_BRACKET,
    TOKEN_RIGHT_BRACKET,
    TOKEN_LEFT_BLOCK,
    TOKEN_RIGHT_BLOCK,
    TOKEN_UNDERLINE,
    LEFT_PAREN,
    RIGHT_PAREN,
    TOKEN_ASSIGN,
    TOKEN_SEMICOLON,
    TOKEN_IF,
    TOKEN_UNROLL,
    TOKEN_LET,
    TOKEN_PLUS,
    TOKEN_STAR,
    TOKEN_RETURN,
    END_OF_FILE
} token_type;


#define is_char(c) isalnum(c) || c == '_'

typedef struct token_t {
    char* literal;
    token_type type;
} token_t;


typedef struct lexer_t{
    token_t* token;
    size_t read_pos;
    size_t pos;
    char ch;
    char* input;
} lexer_t;


char* read_string(lexer_t* l);
char* read_ident(lexer_t* l);
token_type get_type(char* str);
lexer_t* lexer_init(char* s);
token_t* lexer_next_token(lexer_t* l);
void free_token(token_t* tok);

#endif
