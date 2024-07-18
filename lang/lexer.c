#include <ctype.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>

#include "lexer.h"
#include "ut.h"

static int is_number(char* literal) {
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


token_type get_type(char* str) {
    if (strcmp(str, "probe") == 0)
        return TOKEN_PROBE;
    
    if (is_number(str))
        return TOKEN_INT;
    
    return TOKEN_IDENT;
}


lexer_t* lexer_init(char* s) {
    lexer_t* l = checked_malloc(sizeof(*l));
    l->input = ut_str(s);
    l->read_pos = 1;
    l->pos = 0;
    l->ch = l->input[0];

    return l;
}


static 
void read_char(lexer_t* l) {
    if (l->ch) {
        l->pos = l->read_pos;
        l->read_pos++;
        l->ch = l->input[l->pos];
    }
}

static 
void skip_whitespace(lexer_t* l) {
    while (l->ch && (l->ch == ' ' || l->ch == '\n' || l->ch == '\r' || l->ch == '\t')) {
        read_char(l);
    }
}

char* read_string(lexer_t* l) {
    size_t pos = l->pos+1;
	l->pos++;

    while (l->input[l->pos] != '"' && l->input[l->pos] != 0) {
        l->pos++;
    }

    size_t len = l->pos - pos;
    char* str = checked_malloc(len+1);

    memcpy(str, l->input+pos, len);
	str[len] = 0;
    l->pos++;
    l->read_pos = l->pos+1;
    l->ch = l->input[l->pos];
    
	return str;
}

char* read_ident(lexer_t* l) {
    size_t pos = l->pos;

    while (is_char(l->input[l->pos])) {
        l->pos++;
    }
    size_t len = l->pos - pos;

    char* ident = malloc(len + 1);

    if (ident == NULL)
       err(EXIT_FAILURE, "malloc failed");

    memcpy(ident, l->input+pos, len);

    ident[len] = 0;

    l->read_pos = l->pos+1;
    l->ch = l->input[l->pos];
    return ident;
}


token_t* lexer_next_token(lexer_t* l) {
    token_t* t = checked_malloc(sizeof(*t));

    skip_whitespace(l);

    switch (l->ch) {
        case '"':
            t->type = TOKEN_STRING;
            t->literal = read_string(l);
            break;
            
        case ',':
            t->type = TOKEN_COMMA;
            t->literal = strdup(",");
            read_char(l);
            break;
            
        case '/':
            t->type = TOKEN_SLASH;
            t->literal = strdup("/");
            read_char(l);
            break;

        case '(':
            t->type = LEFT_PAREN;
            t->literal = strdup("(");
            read_char(l);
            break;

        case ')':
            t->type = RIGHT_PAREN;
            t->literal = strdup(")");
            read_char(l);
            break;
            
        case '[':
            t->type = TOKEN_LEFT_BRACKET;
            t->literal = strdup("[");
            read_char(l);
            break; 
            
        case ']':
            t->type = TOKEN_RIGHT_BRACKET;
            t->literal = strdup("]");
            read_char(l);
            break;

        case '{':
            t->type = TOKEN_LEFT_BLOCK;
            t->literal = strdup("{");
            read_char(l);
            break;
            
        case '}':
            t->type = TOKEN_RIGHT_BLOCK;
            t->literal = strdup("}");
            read_char(l);
            break;
            
        case ';':
            t->type = TOKEN_SEMICOLON;
            t->literal = strdup(";");
            read_char(l);
            break;
            
        case '=':
            if (l->input[l->read_pos] == '=') {
                t->type = TOKEN_EQ;
                t->literal = strdup("==");
                read_char(l);
                read_char(l);
                break;
            }                  

            t->type = TOKEN_ASSIGN;
            t->literal = strdup("=");
            read_char(l);
            break;
            
        case':':
            t ->type = TOKEN_COLON;
            t->literal = strdup(":");
            read_char(l);
            break;
        
        case '+':
            t->type = TOKEN_PLUS;
            t->literal = strdup("+");
            read_char(l);
            break;
        
        case '*':
            t->type = TOKEN_STAR;
            t->literal = strdup("*");
            read_char(l);
            break;
        
        case 0:
            t->literal = "";
            t->type = END_OF_FILE;
            break;
        
        default:
            if (is_char(l->ch)) {
                t->literal = read_ident(l);
                t->type = get_type(t->literal);
                return t;
            } else {
                t->type = TOKEN_ILLEGAL;
                t->literal = NULL;
                return t;
            }
    }

    return t;
}


void free_token(token_t* tok) {
    if (tok->type != END_OF_FILE) {
        free(tok->literal);
    }
    free(tok);
}

void free_lexer(lexer_t* lex) {
    free(lex->input);
    free(lex);
}
