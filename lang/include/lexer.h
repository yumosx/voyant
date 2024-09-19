#ifndef LEXER_H
#define LEXER_H

#include <stddef.h>

#define is_char(c) isalnum(c) || c == '_'

typedef enum token_type token_type;

enum token_type {
    TOKEN_ILLEGAL,      // Illegal
    TOKEN_INT,          // Integer
    TOKEN_IDENT,        // Identifier
    TOKEN_STRING,       // String
    TOKEN_PROBE,        // Probe
    TOKEN_BEGIN,        // Begin
    TOKEN_END,          // End
    TOKEN_SLASH,        // Slash '/'
    TOKEN_COLON,        // Colon ':'
    TOKEN_COMMA,        // Comma ','
    LEFT_BRACKET,       // Left Bracket '['
    RIGHT_BRACKET,      // Right Bracket ']'
    LEFT_BLOCK,         // Left Block '{'
    RIGHT_BLOCK,        // Right Block '}'
    TOKEN_UNDERLINE,    // Underline '_'
    LEFT_PAREN,         // Left Paren '('
    RIGHT_PAREN,        // Right Paren ')'
    TOKEN_ASSIGN,       // Assign '='
    TOKEN_EQ,           // Equal '=='
    TOKEN_SEMICOLON,    // Semicolon ';'
    TOKEN_IF,           // If
    TOKEN_UNROLL,       // Unroll
    TOKEN_DEC,          // Dec
    TOKEN_PLUS,         // Plus '+'
    TOKEN_STAR,         // Star '*'
    TOKEN_SUB,          // SUB '-'
    TOKEN_GT,           // GT '>'
    TOKEN_HASH,         // Hash '#'
    TOKEN_ACCESS,       // ACCESS '->'
    TOKEN_PIPE,         // Pipe '|'
    END_OF_FILE         // End of File
};

typedef struct token_t {
    char* literal;
    token_type type;
} token_t;

typedef struct lexer_t{
    size_t read_pos;
    size_t pos;
    char ch;
    char* input;
} lexer_t;

char* read_ident(lexer_t* lexer);
token_type get_type(char* string);
lexer_t* lexer_init(char* string);
token_t* lexer_next_token(lexer_t* lexer);

void free_token(token_t* tok);
void free_lexer(lexer_t* lex);

#endif
