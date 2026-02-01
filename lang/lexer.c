#include <ctype.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "lexer.h"
#include "ut.h"

static int is_number(char *literal) {
  if (!*literal)
    return 0;
  while (*literal) {
    if (!isdigit(*literal))
      return 0;
    literal++;
  }
  return 1;
}

token_type classify_token_type(char *str) {
  static const struct {
    const char *keyword;
    token_type type;
  } keywords[] = {
      {"probe", TOKEN_PROBE}, {"BEGIN", TOKEN_BEGIN},   {"END", TOKEN_END},
      {"if", TOKEN_IF},       {"unroll", TOKEN_UNROLL},
  };

  for (size_t i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
    if (strcmp(str, keywords[i].keyword) == 0) {
      return keywords[i].type;
    }
  }

  if (is_number(str))
    return TOKEN_INT;

  return TOKEN_IDENT;
}

lexer_t *lexer_init(char *s) {
  lexer_t *l = vmalloc(sizeof(*l));

  l->input = vstr(s);
  l->read_pos = 1;
  l->pos = 0;
  l->ch = l->input[0];

  return l;
}

static void advance_char(lexer_t *l) {
  if (l->ch) {
    l->pos = l->read_pos;
    l->read_pos++;
    l->ch = l->input[l->pos];
  }
}

static void skip_whitespace(lexer_t *l) {
  while (l->ch &&
         (l->ch == ' ' || l->ch == '\n' || l->ch == '\r' || l->ch == '\t')) {

    advance_char(l);
  }
}

static token_t *make_token(lexer_t *lexer, token_type type,
                           const char *literal) {
  token_t *token = vmalloc(sizeof(*token));
  token->type = type;
  token->literal = strdup(literal);
  advance_char(lexer);
  return token;
}

static token_t *make_token_with_literal(lexer_t *lexer, token_type type,
                                        char *literal) {
  token_t *token = vmalloc(sizeof(*token));
  token->type = type;
  token->literal = literal;
  return token;
}

static token_t *make_two_char_token(lexer_t *lexer, token_type type,
                                    const char *literal) {
  token_t *token = vmalloc(sizeof(*token));
  token->type = type;
  token->literal = strdup(literal);
  advance_char(lexer);
  advance_char(lexer);
  return token;
}

char *scan_string_literal(lexer_t *l) {
  size_t pos = l->pos + 1;
  l->pos++;

  while (l->input[l->pos] != '"' && l->input[l->pos] != 0) {
    l->pos++;
  }

  size_t len = l->pos - pos;
  char *str = vmalloc(len + 1);

  memcpy(str, l->input + pos, len);
  str[len] = 0;
  l->pos++;
  l->read_pos = l->pos + 1;
  l->ch = l->input[l->pos];

  return str;
}

char *scan_identifier(lexer_t *l) {
  size_t pos = l->pos;

  while (is_char(l->input[l->pos])) {
    l->pos++;
  }
  size_t len = l->pos - pos;

  char *ident = vmalloc(len + 1);
  memcpy(ident, l->input + pos, len);
  ident[len] = 0;

  l->read_pos = l->pos + 1;
  l->ch = l->input[l->pos];
  return ident;
}

token_t *lexer_next_token(lexer_t *lexer) {
  skip_whitespace(lexer);

  switch (lexer->ch) {
  case '"':
    return make_token_with_literal(lexer, TOKEN_STRING,
                                   scan_string_literal(lexer));

  case ',':
    return make_token(lexer, TOKEN_COMMA, ",");

  case '(':
    return make_token(lexer, TOKEN_LEFT_PAREN, "(");

  case ')':
    return make_token(lexer, TOKEN_RIGHT_PAREN, ")");

  case '[':
    return make_token(lexer, TOKEN_LEFT_BRACKET, "[");

  case ']':
    return make_token(lexer, TOKEN_RIGHT_BRACKET, "]");

  case '{':
    return make_token(lexer, TOKEN_LEFT_BRACE, "{");

  case '}':
    return make_token(lexer, TOKEN_RIGHT_BRACE, "}");

  case ';':
    return make_token(lexer, TOKEN_SEMICOLON, ";");

  case '+':
    return make_token(lexer, TOKEN_PLUS, "+");

  case '*':
    return make_token(lexer, TOKEN_STAR, "*");

  case '#':
    return make_token(lexer, TOKEN_HASH, "#");

  case '/':
    if (lexer->input[lexer->read_pos] == '/') {
      while (lexer->input[lexer->pos] != '\n') {
        advance_char(lexer);
      }
      return lexer_next_token(lexer);
    }
    return make_token(lexer, TOKEN_SLASH, "/");

  case '<':
    if (lexer->input[lexer->read_pos] == '=') {
      return make_two_char_token(lexer, TOKEN_LE, "<=");
    }
    return make_token(lexer, TOKEN_LT, "<");

  case '>':
    if (lexer->input[lexer->read_pos] == '=') {
      return make_two_char_token(lexer, TOKEN_GE, ">=");
    }
    return make_token(lexer, TOKEN_GT, ">");

  case '-':
    if (lexer->input[lexer->read_pos] == '>') {
      return make_two_char_token(lexer, TOKEN_ACCESS, "->");
    }
    return make_token(lexer, TOKEN_SUB, "-");

  case '|':
    if (lexer->input[lexer->read_pos] == '>') {
      return make_two_char_token(lexer, TOKEN_PIPE, "|>");
    }
    break;

  case '=':
    if (lexer->input[lexer->read_pos] == '=') {
      return make_two_char_token(lexer, TOKEN_EQ, "==");
    }
    return make_token(lexer, TOKEN_ASSIGN, "=");

  case ':':
    if (lexer->input[lexer->read_pos] == '=') {
      return make_two_char_token(lexer, TOKEN_DECLARE, ":=");
    }
    return make_token(lexer, TOKEN_COLON, ":");

  case 0: {
    token_t *token = vmalloc(sizeof(*token));
    token->literal = "";
    token->type = TOKEN_EOF;
    return token;
  }
  default:
    break;
  }

  if (is_char(lexer->ch)) {
    char *ident = scan_identifier(lexer);
    return make_token_with_literal(lexer, classify_token_type(ident), ident);
  }

  token_t *token = vmalloc(sizeof(*token));
  token->type = TOKEN_ILLEGAL;
  token->literal = NULL;
  return token;
}

const char *token_to_str(token_type type) {
#define TYPE(_type, _type_str) [_type] = _type_str,
  static const char *strs[] = {TOKEN_TYPE_TABLE};
#undef TYPE
  return strs[type];
}

void token_destroy(token_t *tok) {
  if (tok->type != TOKEN_EOF) {
    free(tok->literal);
  }
  free(tok);
}

void lexer_destroy(lexer_t *lex) {
  free(lex->input);
  free(lex);
}