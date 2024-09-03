#include <stdlib.h>
#include <stdio.h>

#include "lexer.h"
#include "parser.h"
#include "ut.h"

void p_next_tok(parser_t* p) {    
    if (p->this_tok != NULL) {
		free_token(p->this_tok);
	}
	p->this_tok = p->next_tok;
    p->next_tok = lexer_next_token(p->lexer);
}

int this_tok_is(parser_t* p, token_type type) {
    return p->this_tok->type == type;
}

int next_tok_is(parser_t* p, token_type type) {
    return p->next_tok->type == type;
}

parser_t* parser_init(lexer_t* l) {
    parser_t* p = vmalloc(sizeof(*p));
    p->lexer = l;
    p->this_tok = NULL;
    p->next_tok = NULL;

    p_next_tok(p);
    p_next_tok(p);

    return p;
}

int expect_peek(parser_t* p, token_type t) {
    if (next_tok_is(p, t)) {
        p_next_tok(p);
        return 1;
    }
    return 0;
}

static seq_t 
get_token_seq(token_type t) {
    switch (t) {
    case TOKEN_EQ:
        return EQUALS;  
    case TOKEN_PLUS:
        return SUM;
    case TOKEN_STAR:
        return PRODUCT;
    case LEFT_PAREN:
        return CALL;
    case TOKEN_LEFT_BRACKET:
        return INDEX;
    case TOKEN_ASSIGN:
        return ASSIGN;
    case TOKEN_DEC:
        return DEC;
    case TOKEN_PIPE:
        return PIPE;
    default:
        return LOWEST;
    }
}

int get_op(token_type t) {
    switch (t) {
    case TOKEN_ASSIGN:
        return OP_MOV;

    case TOKEN_STAR:
        return OP_MUL;

    case TOKEN_PLUS:
        return OP_ADD;
    
    case TOKEN_PIPE:
        return OP_PIPE;
    
    case TOKEN_EQ:
        return JUMP_JEQ;
    default:
        break;
    }
}

node_t* parse_int_expr(char* name) {
   	size_t integer = 0;
    char* s = name;

    while (*s != '\0') {
        integer = (integer * 10) + (*s++ - '0');
    }
	
	return node_int_new(integer);
}

node_t* parse_dec_expr(parser_t* p, node_t* var) {
    node_t* expr;
    int seq;

    seq = get_token_seq(p->this_tok->type);
    p_next_tok(p);
    expr = parse_expr(p, seq);    
    return node_dec_new(var, expr);  
}

node_t* parse_assign_expr(parser_t* p, node_t* left) {
	op_t op;
	node_t* right;
    int seq;
    
    seq = get_token_seq(p->this_tok->type);
    p_next_tok(p);
    right = parse_expr(p, seq); 

    return node_assign_new(left, right);
}

node_t* parse_infix_expr(parser_t* p, node_t* left) {
	node_t* right; 
	seq_t seq; 
	int opcode;
    
	opcode = get_op(p->this_tok->type);
    seq = get_token_seq(p->this_tok->type);
    p_next_tok(p);
    
    right = parse_expr(p, seq);
    
    return node_expr_new(opcode, left, right); 
}

node_t* parse_call_args(parser_t* p) {
    node_t* n, *head;
    
    p_next_tok(p);
    
    n = parse_expr(p, LOWEST);
    head = n;
        
    while (next_tok_is(p, TOKEN_COMMA)) {
        p_next_tok(p);
        p_next_tok(p);
        n->next = parse_expr(p, LOWEST);
        n = n->next;
    }

    if (!expect_peek(p, RIGHT_PAREN)) {
        _errmsg("expect a right paren");
        return NULL;
    }

    return head;
}

node_t* parse_call_expr(parser_t* p, node_t* left) {
    left->type = NODE_CALL;
    
	if (next_tok_is(p, RIGHT_PAREN)) {
		p_next_tok(p);
		return left;
	}

	left->call.args = parse_call_args(p);
    return left;
}


node_t* parse_map_args(parser_t* p) {
    node_t* n, *head;
    
    n = parse_expr(p, LOWEST);
    head = n;
    
    while (next_tok_is(p, TOKEN_COMMA)) {
        p_next_tok(p);
        p_next_tok(p);
        n->next = parse_expr(p, LOWEST);
        n = n->next;
    }

    if (!expect_peek(p, TOKEN_RIGHT_BRACKET)) {
        _errmsg("expected a right bucket, but get a different token");
        return NULL;
    }

    return head;
}

node_t* parse_map_expr(parser_t* p, node_t* left) {
    left->type = NODE_MAP;
    p_next_tok(p);
    left->map.args = parse_map_args(p);
    return left;
}

node_t* parse_unroll_stmts(parser_t* p) {
    char* str;
    node_t* stmts;
    size_t count = 0;

    if (!expect_peek(p, LEFT_PAREN)) {
        return NULL;
    }
    str = p->next_tok->literal;

    while (*str != '\0') {
        count = (count * 10) + (*str++ - '0');
    }
    p_next_tok(p);

    if (!expect_peek(p, RIGHT_PAREN)) {
        return NULL;
    }
    p_next_tok(p);

    stmts = parse_block_stmts(p);

    return node_unroll_new(count, stmts);
}


node_t* parse_expr(parser_t* p, seq_t s) {    
    node_t* left;

    switch (p->this_tok->type) {
        case TOKEN_INT:
            left = parse_int_expr(p->this_tok->literal);
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
        default:
            return NULL;
    }
    
    while (!next_tok_is(p, TOKEN_SEMICOLON) && s < get_token_seq(p->next_tok->type)) {
        switch (p->next_tok->type) {
        case TOKEN_PIPE:
        case TOKEN_STAR:
        case TOKEN_PLUS:
            p_next_tok(p);
            left = parse_infix_expr(p, left);
            break;
        case LEFT_PAREN:
            p_next_tok(p);
            left = parse_call_expr(p, left);
            break;
        case TOKEN_LEFT_BRACKET:
            p_next_tok(p);
            left = parse_map_expr(p, left);
            break;
        case TOKEN_DEC:
            p_next_tok(p);
            left = parse_dec_expr(p, left);
            break;
        case TOKEN_ASSIGN:
            p_next_tok(p);
            left = parse_assign_expr(p, left);
            break;
        default:
            break;
        }
    }

    return left;
}

node_t* parse_block_stmts(parser_t* p) {
    node_t* n, *head;
    
    p_next_tok(p);

    n = parse_expr(p, LOWEST);
    head = n;
    
    p_next_tok(p);
    
    while (!next_tok_is(p, TOKEN_RIGHT_BLOCK) && !next_tok_is(p, END_OF_FILE)) {
        node_t* stmts = parse_expr(p, LOWEST);

        if (stmts != NULL) {
            n->next = stmts;
            n = n->next;
        }

        p_next_tok(p);
    }

    return head;
}

node_t* parse_probe(parser_t* p) {
	char* name;
	node_t* stmts, *prev;
    
    if (!expect_peek(p, TOKEN_IDENT)) {
        verror("expect a ident for probe");
        return NULL;
    }

    name = strdup(p->this_tok->literal);
	p_next_tok(p);
	
	if (p->this_tok->type == TOKEN_SLASH) {
        p_next_tok(p);
		prev = parse_expr(p, LOWEST);
        p_next_tok(p);
        p_next_tok(p);
    }
    
    stmts = parse_block_stmts(p);
    
    return node_probe_new(name, stmts);     
}

node_t* parse_script(parser_t* p) {
    char* name;
    node_t* stmts;
    
    name = p->this_tok->literal;

    if (vstreq(name, "BEGIN")) {
        p_next_tok(p);
        stmts = parse_block_stmts(p); 
        p_next_tok(p);
        p_next_tok(p);

        return node_probe_new("BEGIN", stmts);
    }

    if (vstreq(name, "END")) {
        p_next_tok(p);
        stmts = parse_block_stmts(p);
        p_next_tok(p);
        p_next_tok(p);

        return node_probe_new("END", stmts);
    }

    if (vstreq(name, "probe")) {
        return parse_probe(p);
    }
}

node_t* parse_program(parser_t* p) {
    node_t* n, *head;
    
    n = parse_script(p);
    head = n;
    
    while (p->next_tok->type != END_OF_FILE) {
        node_t* script = parse_script(p);
        if (script) {
            n->next = script;
            n = n->next;
        }
        p_next_tok(p); 
    }
    
    return head;
}

void free_parser(parser_t* p) {
    free_lexer(p->lexer);
    free_token(p->this_tok);
    free_token(p->next_tok);
}