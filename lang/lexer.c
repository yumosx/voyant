#include <ctype.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>

#include "lexer.h"
#include "ut.h"

static int is_number(char *literal) {
    while (1) {
        char c = *literal;
        if (!c)
            break;
        if (!isdigit(c))
            return 0;
        literal++;
    }
    return 1;
}

token_type get_type(char *str) {
    if (strcmp(str, "probe") == 0)
        return TOKEN_PROBE;

    if (vstreq(str, "BEGIN"))
        return TOKEN_BEGIN;

    if (vstreq(str, "END"))
        return TOKEN_END;

    if (!strcmp(str, "if"))
        return TOKEN_IF;

    if (!strcmp(str, "unroll"))
        return TOKEN_UNROLL;

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

static void read_char(lexer_t *l) {
    if (l->ch) {
        l->pos = l->read_pos;
        l->read_pos++;
        l->ch = l->input[l->pos];
    }
}

static void skip_whitespace(lexer_t *l) {
    while (l->ch && (l->ch == ' ' 
        || l->ch == '\n' 
        || l->ch == '\r' 
        || l->ch == '\t')) {
        
        read_char(l);
    }
}

char *read_string(lexer_t *l) {
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

char *read_ident(lexer_t *l) {
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

token_t* lexer_next_token(lexer_t *lexer) {
    token_t* token = vmalloc(sizeof(*token));

    skip_whitespace(lexer);

    switch (lexer->ch) {
    case '"':
        token->type = TOKEN_STRING;
        token->literal = read_string(lexer);
        return token;

    case ',':
        token->type = TOKEN_COMMA;
        token->literal = strdup(",");
        read_char(lexer);
        return token;

    case '/':
        token->type = TOKEN_SLASH;
        token->literal = strdup("/");
        read_char(lexer);
        return token;
    
    case '(':
        token->type = LEFT_PAREN;
        token->literal = strdup("(");
        read_char(lexer);
        return token;
    
    case ')':
        token->type = RIGHT_PAREN;
        token->literal = strdup(")");
        read_char(lexer);
        return token;

    case '[':
        token->type = LEFT_BRACKET;
        token->literal = strdup("[");
        read_char(lexer);
        return token;

    case ']':
        token->type = RIGHT_BRACKET;
        token->literal = strdup("]");
        read_char(lexer);
        return token;

    case '{':
        token->type = LEFT_BLOCK;
        token->literal = strdup("{");
        read_char(lexer);
        return token;

    case '}':
        token->type = RIGHT_BLOCK;
        token->literal = strdup("}");
        read_char(lexer);
        return token;

    case ';':
        token->type = TOKEN_SEMICOLON;
        token->literal = strdup(";");
        read_char(lexer);
        return token;

    case '+':
        token->type = TOKEN_PLUS;
        token->literal = strdup("+");
        read_char(lexer);
        return token;

    case '*':
        token->type = TOKEN_STAR;
        token->literal = strdup("*");
        read_char(lexer);
        return token;

    case '#':
        token->type = TOKEN_HASH;
        token->literal = strdup("#");
        read_char(lexer);
        return token;
    
    case '<':
        if (lexer->input[lexer->read_pos] == '=') {
            token->type = TOKEN_LE;
            token->literal = strdup("<=");
            read_char(lexer);
            read_char(lexer);
            return token;
        }
        
        token->type = TOKEN_LT;
        token->literal = strdup("<");
        read_char(lexer);
        return token;

    case '>':
        if (lexer->input[lexer->read_pos] == '=') {
            token->type = TOKEN_GE;
            token->literal = strdup(">=");
            read_char(lexer);
            read_char(lexer);
            return token;
        }
        
        token->type = TOKEN_GT;
        token->literal = strdup(">");
        read_char(lexer);
        return token;

    case '-':
        if (lexer->input[lexer->read_pos] == '>') {
            token->type = TOKEN_ACCESS;
            token->literal = strdup("->");
            read_char(lexer);
            read_char(lexer);
            return token;
        }

        token->type = TOKEN_SUB;
        token->literal = strdup("-");
        read_char(lexer);
        return token;
    
    case '|':
        if (lexer->input[lexer->read_pos] == '>') {
            token->type = TOKEN_PIPE;
            token->literal = strdup("|>");
            read_char(lexer);
            read_char(lexer);
            return token;
        }
    
    case '=':
        if (lexer->input[lexer->read_pos] == '=') {
            token->type = TOKEN_EQ;
            token->literal = strdup("==");
            read_char(lexer);
            read_char(lexer);
            return token;
        }

        token->type = TOKEN_ASSIGN;
        token->literal = strdup("=");
        read_char(lexer);
        return token;

    case ':':
        if (lexer->input[lexer->read_pos] == '=') {
            token->type = TOKEN_DEC;
            token->literal = strdup(":=");
            read_char(lexer);
            read_char(lexer);
            return token;
        }
    case 0:
        token->literal = "";
        token->type = END_OF_FILE;
        return token;
    default:
        goto out;
        break;        
    }

out:
    if (is_char(lexer->ch)) {
        token->literal = read_ident(lexer);
        token->type = get_type(token->literal);
        return token;
    } else {
        token->type = TOKEN_ILLEGAL;
        token->literal = NULL;
        return token;
    }
}


const char* token_to_str(token_type type) {
#define TYPE(_type, _type_str) [_type] = _type_str,
    static const char* strs[] = {
        TOKEN_TYPE_TABLE
    };
#undef TYPE
    return strs[type];
}

void free_token(token_t *tok) {
    if (tok->type != END_OF_FILE) {
        free(tok->literal);
    }
    free(tok);
}

void free_lexer(lexer_t *lex) {
    free(lex->input);
    free(lex);
}