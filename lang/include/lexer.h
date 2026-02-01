#ifndef LEXER_H
#define LEXER_H

#include <stddef.h>

#define is_char(c) isalnum(c) || c == '_'

#define TOKEN_TYPE_TABLE                                                       \
  TYPE(TOKEN_ILLEGAL, "Illegal")                                               \
  TYPE(TOKEN_INT, "Int")                                                       \
  TYPE(TOKEN_IDENT, "Ident")                                                   \
  TYPE(TOKEN_STRING, "String")                                                 \
  TYPE(TOKEN_PROBE, "Probe")                                                   \
  TYPE(TOKEN_KPROBE, "Kprobe")                                                 \
  TYPE(TOKEN_BEGIN, "Begin")                                                   \
  TYPE(TOKEN_END, "End")                                                       \
  TYPE(TOKEN_SLASH, "Slash")                                                   \
  TYPE(TOKEN_COLON, "Colon")                                                   \
  TYPE(TOKEN_COMMA, "Comma")                                                   \
  TYPE(TOKEN_LEFT_BRACKET, "Left Bracket")                                     \
  TYPE(TOKEN_RIGHT_BRACKET, "Right Bracket")                                   \
  TYPE(TOKEN_LEFT_BRACE, "Left Brace")                                         \
  TYPE(TOKEN_RIGHT_BRACE, "Right Brace")                                       \
  TYPE(TOKEN_UNDERLINE, "Underline")                                           \
  TYPE(TOKEN_LEFT_PAREN, "Left Paren")                                         \
  TYPE(TOKEN_RIGHT_PAREN, "Right Paren")                                       \
  TYPE(TOKEN_ASSIGN, "Assign")                                                 \
  TYPE(TOKEN_EQ, "Equal")                                                      \
  TYPE(TOKEN_SEMICOLON, "Semicolon")                                           \
  TYPE(TOKEN_IF, "If")                                                         \
  TYPE(TOKEN_UNROLL, "Unroll")                                                 \
  TYPE(TOKEN_DECLARE, "Declare")                                               \
  TYPE(TOKEN_PLUS, "Plus")                                                     \
  TYPE(TOKEN_STAR, "Star")                                                     \
  TYPE(TOKEN_SUB, "Sub")                                                       \
  TYPE(TOKEN_GE, "Ge")                                                         \
  TYPE(TOKEN_GT, "Gt")                                                         \
  TYPE(TOKEN_LT, "Lt")                                                         \
  TYPE(TOKEN_LE, "Le")                                                         \
  TYPE(TOKEN_HASH, "Hash")                                                     \
  TYPE(TOKEN_ACCESS, "Access")                                                 \
  TYPE(TOKEN_PIPE, "Pipe")                                                     \
  TYPE(TOKEN_EOF, "End of File")

#define TYPE(_type, _typestr) _type,
typedef enum token_type { TOKEN_TYPE_TABLE } token_type;
#undef TYPE

typedef struct token_t {
  char *literal;
  token_type type;
} token_t;

typedef struct lexer_t {
  size_t read_pos;
  size_t pos;
  char ch;
  char *input;
} lexer_t;

char *scan_identifier(lexer_t *lexer);
token_type classify_token_type(char *string);
lexer_t *lexer_init(char *string);
token_t *lexer_next_token(lexer_t *lexer);

void token_destroy(token_t *tok);
void lexer_destroy(lexer_t *lex);

const char *token_to_str(token_type type);

#endif
