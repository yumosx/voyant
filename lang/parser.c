#include <stdlib.h>
#include <stdio.h>

#include "lexer.h"
#include "parser.h"
#include "ut.h"

void advance(parser_t* p) {    
    if (p->this_tok != NULL) {
		free_token(p->this_tok);
	}
	
    p->this_tok = p->next_tok;
    p->next_tok = lexer_next_token(p->lexer);
}

static int 
current_token_is(parser_t* p, token_type type) {
    return p->this_tok->type == type;
}

static int  
next_token_is(parser_t* p, token_type type) {
    return p->next_tok->type == type;
}

parser_t* parser_init(lexer_t* l) {
    parser_t* p = vmalloc(sizeof(*p));
    p->lexer = l;
    p->this_tok = NULL;
    p->next_tok = NULL;

    advance(p);
    advance(p);

    return p;
}

int expect_next_token(parser_t* p, token_type t) {
    if (next_token_is(p, t)) {
        advance(p);
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
    case TOKEN_GT:
        return LESSGREATERA;
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

    case TOKEN_GT:
        return JUMP_JGT;

    case TOKEN_EQ:
        return JUMP_JEQ;
    default:
        break;
    }
}

node_t* parse_integer(char* name) {
   	size_t integer = 0;
    char* s = name;

    while (*s != '\0') {
        integer = (integer * 10) + (*s++ - '0');
    }
	
	return node_int_new(integer);
}

node_t* parse_dec(parser_t* p, node_t* var) {
    node_t* expr;
    int seq;

    seq = get_token_seq(p->this_tok->type);
    advance(p);
    expr = parse_expr(p, seq);    

    return node_dec_new(var, expr);  
}

node_t* parse_assign(parser_t* p, node_t* left) {
	op_t op;
	node_t* right;
    int seq;
    
    seq = get_token_seq(p->this_tok->type);
    advance(p);
    right = parse_expr(p, seq); 

    return node_assign_new(left, right);
}

node_t* parse_infix_expr(parser_t* p, node_t* left) {
	node_t* right; 
	seq_t seq; 
	int opcode;
    
	opcode = get_op(p->this_tok->type);
    seq = get_token_seq(p->this_tok->type);
    advance(p);
    
    right = parse_expr(p, seq);
    
    return node_expr_new(opcode, left, right); 
}

node_t* parse_call_args(parser_t* p) {
    node_t* n, *head;
    
    advance(p);
    
    n = parse_expr(p, LOWEST);
    head = n;
        
    while (next_token_is(p, TOKEN_COMMA)) {
        advance(p);
        advance(p);
        n->next = parse_expr(p, LOWEST);
        n = n->next;
    }

    if (!expect_next_token(p, RIGHT_PAREN)) {
        _errmsg("expect a right paren");
        return NULL;
    }

    return head;
}

node_t* parse_call_expr(parser_t* p, node_t* left) {
    left->type = NODE_CALL;
    
	if (next_token_is(p, RIGHT_PAREN)) {
		advance(p);
		return left;
	}

	left->call.args = parse_call_args(p);
    return left;
}

node_t* parse_map_args(parser_t* p) {
    node_t* n, *head;
    
    n = parse_expr(p, LOWEST);
    head = n;
    
    while (next_token_is(p, TOKEN_COMMA)) {
        advance(p);
        advance(p);
        n->next = parse_expr(p, LOWEST);
        n = n->next;
    }

    if (!expect_next_token(p, TOKEN_RIGHT_BRACKET)) {
        return NULL;
    }

    return head;
}

node_t* parse_map_expr(parser_t* p, node_t* left) {
    left->type = NODE_MAP;
    advance(p);
    left->map.args = parse_map_args(p);
    return left;
}

node_t* parse_unroll_stmts(parser_t* p) {
    char* str;
    node_t* stmts;
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

node_t* parse_if_stmts(parser_t* p) {
    node_t* cond, *stmts, *els;

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

node_t* parse_expr(parser_t* p, seq_t s) {    
    node_t* left;

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
    
    while (!next_token_is(p, TOKEN_SEMICOLON) && s < get_token_seq(p->next_tok->type)) {
        switch (p->next_tok->type) {
        case TOKEN_GT:
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
        case TOKEN_LEFT_BRACKET:
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

node_t* parse_block_stmts(parser_t* p) {
    node_t* n, *head;
    
    advance(p);

    n = parse_expr(p, LOWEST);
    head = n;
    
    advance(p);
    
    while (!next_token_is(p, TOKEN_RIGHT_BLOCK) && !next_token_is(p, END_OF_FILE)) {
        node_t* stmts = parse_expr(p, LOWEST);

        if (stmts != NULL) {
            n->next = stmts;
            n = n->next;
        }

        advance(p);
    }

    advance(p);
    return head;
}

node_t* parse_probe(parser_t* p) {
	char* name;
	node_t* stmts, *prev;
    
    if (!expect_next_token(p, TOKEN_IDENT)) {
        verror("expect a ident for probe");
        return NULL;
    }

    name = strdup(p->this_tok->literal);
	advance(p);
	
	if (p->this_tok->type == TOKEN_SLASH) {
        advance(p);
		prev = parse_expr(p, LOWEST);
        advance(p);
        advance(p);
    }
    
    stmts = parse_block_stmts(p);
    
    return node_probe_new(name, stmts);     
}

node_t* parse_script(parser_t* p) {
    char* name;
    node_t* stmts;
    
    name = p->this_tok->literal;

    if (vstreq(name, "BEGIN") || vstreq(name, "END")) {
        name = strdup(name);
        advance(p);
        
        stmts = parse_block_stmts(p); 
        advance(p);

        return node_probe_new(name, stmts);
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
        advance(p); 
    }

    free_parser(p);
    return head;
}

void free_parser(parser_t* p) {
    free_lexer(p->lexer);
    free_token(p->this_tok);
    free_token(p->next_tok);
}