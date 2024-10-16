#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include "lexer.h"
#include "parser.h"
#include "ut.h"

static bool current(parser_t *parser, token_type type) {
    return parser->this_tok->type == type;
}

static bool expect(parser_t *parser, token_type type) {
    return parser->next_tok->type == type;
}

static void advance(parser_t *parser) {
    if (parser->this_tok != NULL)
        free_token(parser->this_tok);

    parser->this_tok = parser->next_tok;
    parser->next_tok = lexer_next_token(parser->lexer);
}

static void bad_token(parser_t* parser, token_type type, bool is_next) {
    char* token, *expect;
    
    if (is_next) {
        token = parser->this_tok->literal;
        expect = token_to_str(type);
        
        verror("Parsing error: expected next token to be [%s], got [%s] instead", expect, token);
        return;
    }

    printf("%s %s\n", token, expect);
    token = parser->this_tok->literal;
    expect = token_to_str(type);

    verror("Parser error: expected this token to be [%s] got [%s] instead", expect, token);

}

parser_t *parser_init(lexer_t *lexer) {
    parser_t *parser = vmalloc(sizeof(*parser));
    
    parser->lexer = lexer;
    parser->this_tok = NULL;
    parser->next_tok = NULL;

    advance(parser);
    advance(parser);

    return parser;
}

bool expect_next_token(parser_t* parser, token_type type) {
    if (expect(parser, type)) {
        advance(parser);
        return true;
    }

    return false;
}

static seq_t
get_token_seq(token_type type) {
    switch (type) {
    case TOKEN_EQ:
        return EQUALS;

    case TOKEN_SUB:
        return SUM;
    
    case TOKEN_PLUS:
        return SUM;
    
    case TOKEN_STAR:
        return PRODUCT;
    
    case TOKEN_SLASH:
        return PRODUCT;

    case LEFT_PAREN:
        return CALL;
    
    case LEFT_BRACKET:
        return INDEX;
    
    case TOKEN_ASSIGN:
        return ASSIGN;
    
    case TOKEN_DEC:
        return DEC;
    
    case TOKEN_PIPE:
        return PIPE;

    case TOKEN_LE:
    case TOKEN_LT:
    case TOKEN_GE: 
    case TOKEN_GT:
        return LESSGREATERA;
    
    case TOKEN_ACCESS:
        return SUM;
    default:
        return LOWEST;
    }
}

static int get_op(token_type type) {
    switch (type) {
    case TOKEN_ASSIGN:
        return OP_MOV;

    case TOKEN_STAR:
        return OP_MUL;

    case TOKEN_PLUS:
        return OP_ADD;
    
    case TOKEN_SUB:
        return OP_SUB;

    case TOKEN_SLASH:
        return OP_DIV;

    case TOKEN_PIPE:
        return OP_PIPE;

    case TOKEN_GE:
        return OP_GE;

    case TOKEN_GT:
        return OP_GT;

    case TOKEN_LT:
        return OP_LT;

    case TOKEN_LE:
        return OP_LE;

    case TOKEN_EQ:
        return OP_EQ;
    
    case TOKEN_ACCESS:
        return OP_ACCESS;
        
    default:
        return OP_ILLEGAL;
    }
}

static node_t *parse_integer(char *name) {
    size_t integer = 0;
    char *s = name;

    while (*s != '\0') {
        integer = (integer * 10) + (*s++ - '0');
    }

    return node_int_new(integer);
}

static node_t* parse_dec(parser_t *parser, node_t *var) {
    node_t* expr;
    int seq;

    seq = get_token_seq(parser->this_tok->type);
    advance(parser);
    expr = parse_expr(parser, seq);

    return node_dec_new(var, expr);
}

node_t* parse_assign(parser_t *parser, node_t *left) {
    node_t *right;
    int seq;

    seq = get_token_seq(parser->this_tok->type);
    advance(parser);
    right = parse_expr(parser, seq);

    return node_assign_new(left, right);
}

node_t* parse_infix_expr(parser_t *parser, node_t *left) {
    node_t *right;
    seq_t seq;
    int opcode;

    opcode = get_op(parser->this_tok->type);
    seq = get_token_seq(parser->this_tok->type);
    advance(parser);

    right = parse_expr(parser, seq);

    return node_expr_new(opcode, left, right);
}

node_t* parse_call_args(parser_t* parser) {
    node_t *n, *head;

    advance(parser);

    n = parse_expr(parser, LOWEST);
    head = n;

    while (expect(parser, TOKEN_COMMA)) {
        advance(parser);
        advance(parser);
        n->next = parse_expr(parser, LOWEST);
        n = n->next;
    }

    if (!expect_next_token(parser, RIGHT_PAREN)) {
        verror("expect a right paren");
        return NULL;
    }

    return head;
}

node_t *parse_call_expr(parser_t *parser, node_t *left) {
    left->type = NODE_CALL;

    if (expect(parser, RIGHT_PAREN)) {
        advance(parser);
        return left;
    }

    left->call.args = parse_call_args(parser);
    return left;
}

node_t *parse_map_args(parser_t *p) {
    node_t *n, *head;

    n = parse_expr(p, LOWEST);
    head = n;

    while (expect(p, TOKEN_COMMA)) {
        advance(p);
        advance(p);
        n->next = parse_expr(p, LOWEST);
        n = n->next;
    }

    if (!expect_next_token(p, RIGHT_BRACKET)) {
        return NULL;
    }

    return head;
}

node_t *parse_map_expr(parser_t *p, node_t *left) {
    left->type = NODE_MAP;
    advance(p);
    left->map.args = parse_map_args(p);
    return left;
}

node_t *parse_unroll_stmts(parser_t *p) {
    char *str;
    node_t *stmts;
    size_t count = 0;

    if (!expect_next_token(p, LEFT_PAREN)) {
        return NULL;
    }
    
    str = p->next_tok->literal;

    while (*str != '\0') {
        count = (count * 10) + (*str++ - '0');
    }
    advance(p);

    if (!expect_next_token(p, RIGHT_PAREN)) {
        return NULL;
    }
    advance(p);

    stmts = parse_block_stmts(p);
    return node_unroll_new(count, stmts);
}

node_t *parse_if_stmts(parser_t *p) {
    node_t *cond, *stmts;

    if (!expect_next_token(p, LEFT_PAREN)) {
        return NULL;
    }

    advance(p);
    cond = parse_expr(p, LOWEST);
    advance(p);
    advance(p);

    stmts = parse_block_stmts(p);

    return node_if_new(cond, stmts, NULL);
}

node_t *parse_expr(parser_t *p, seq_t s) {
    node_t *left;

    switch (p->this_tok->type) {
    case TOKEN_INT:
        left = parse_integer(p->this_tok->literal);
        break;
    case TOKEN_IDENT:
        left = node_var_new(vstr(p->this_tok->literal));
        break;
    case TOKEN_STRING:
        left = node_str_new(vstr(p->this_tok->literal));
        break;
    case TOKEN_UNROLL:
        left = parse_unroll_stmts(p);
        break;
    case TOKEN_IF:
        left = parse_if_stmts(p);
        break;
    default:
        return NULL;
    }
    
    while (!expect(p, TOKEN_SEMICOLON) && s < get_token_seq(p->next_tok->type)) {
        switch (p->next_tok->type) {
        case TOKEN_SLASH:
        case TOKEN_EQ:
        case TOKEN_ACCESS:
        case TOKEN_GE:
        case TOKEN_GT:
        case TOKEN_LE:
        case TOKEN_LT:
        case TOKEN_SUB:
        case TOKEN_PIPE:
        case TOKEN_STAR:
        case TOKEN_PLUS:
            advance(p);
            left = parse_infix_expr(p, left);
            break;
        case LEFT_PAREN:
            advance(p);
            left = parse_call_expr(p, left);
            break;
        case LEFT_BRACKET:
            advance(p);
            left = parse_map_expr(p, left);
            break;
        case TOKEN_DEC:
            advance(p);
            left = parse_dec(p, left);
            break;
        case TOKEN_ASSIGN:
            advance(p);
            left = parse_assign(p, left);
            break;
        default:
            break;
        }
    }

    return left;
}

node_t *parse_block_stmts(parser_t *p) {
    node_t *n, *head;

    advance(p);

    n = parse_expr(p, LOWEST);
    head = n;

    advance(p);

    while (!expect(p, RIGHT_BLOCK) && !expect(p, END_OF_FILE)) {
        node_t *stmts = parse_expr(p, LOWEST);

        if (stmts != NULL) {
            n->next = stmts;
            n = n->next;
        }
        advance(p);
    }
    advance(p);
    return head;
}

node_t* parse_probe(parser_t* parser, char* event) {
    char* name;
    int flag = 0;
    node_t* stmts, *pred;

    if (!expect_next_token(parser, TOKEN_IDENT)) {
        return NULL;
    }

    name = strdup(parser->this_tok->literal);
    
    if (!vstreq("kprobe", event) && event) {
        flag = 1;
        char* str = calloc(100, sizeof(char));
        snprintf(str, 100, "%s/%s", event, name);
        free(name);
        name = str;
    }
    
    advance(parser);

    if (parser->this_tok->type == TOKEN_SLASH) {
        advance(parser);
        pred = parse_expr(parser, LOWEST);
        advance(parser);
        advance(parser);
    }

    stmts = parse_block_stmts(parser);

    if (!flag) {
        return node_kprobe_new(name, stmts);
    }

    return node_probe_new(name, stmts);
}


node_t* parse_script(parser_t* parser, char* event) {
    char* name;
    node_t* stmts;

    name = parser->this_tok->literal;

    if (current(parser, TOKEN_BEGIN) || current(parser, TOKEN_END)) {
        name = strdup(name);
        advance(parser);

        stmts = parse_block_stmts(parser);
        advance(parser);

        return node_test_new(name, stmts);
    }

    if (current(parser, TOKEN_PROBE)) {
        stmts = parse_probe(parser, event);
        advance(parser);
        return stmts;
    }

    return NULL;
}

char* parse_event(parser_t *parser) {
    if (!current(parser, TOKEN_HASH)) {
        bad_token(parser, TOKEN_HASH, false);
        return NULL;
    }

    char* name;

    if (!expect_next_token(parser, TOKEN_IDENT)) {
        bad_token(parser, TOKEN_IDENT, true);
        return NULL;
    }

    name = strdup(parser->this_tok->literal);

    if (!expect_next_token(parser, TOKEN_SEMICOLON)) {
        bad_token(parser, TOKEN_SEMICOLON, true);
        return NULL;
    }

    return name;
}

node_t* parse_program(parser_t* parser) {
    char* name;
    node_t* head, *node;

    name = parse_event(parser);
    advance(parser);

    node = parse_script(parser, name);
    
    head = node;
    head->name = name;

    while (parser->next_tok->type != END_OF_FILE){
        node_t *script = parse_script(parser, name);
        if (script) {
            node->next = script;
            node = node->next;
        }
    }

    free_parser(parser);

    return head;
}

void free_parser(parser_t *parser) {
    free_lexer(parser->lexer);
    free_token(parser->this_tok);
    free_token(parser->next_tok);
}