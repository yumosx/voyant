#ifndef LEXER_H
#define LEXER_H

#include <stddef.h>

#define is_char(c) isalnum(c) || c == '_'
#define get_token_name(tok) tok_type_str[tok->type]

extern const char* tok_type_str[];

typedef enum token_type token_type;
typedef struct token_t token_t;
typedef struct lexer_t lexer_t;

enum token_type{
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
    TOKEN_EQ,
    TOKEN_SEMICOLON,
    TOKEN_IF,
    TOKEN_UNROLL,
    TOKEN_LET,
    TOKEN_PLUS,
    TOKEN_STAR,
    TOKEN_RETURN,
    END_OF_FILE
};

struct token_t {
    char* literal;
    token_type type;
};

struct lexer_t{
    size_t read_pos;
    size_t pos;
    char ch;
    char* input;
};

char* read_ident(lexer_t* l);
token_type get_type(char* str);
lexer_t* lexer_init(char* s);
token_t* lexer_next_token(lexer_t* l);

void free_token(token_t* tok);
void free_lexer(lexer_t* lex);

#endif
