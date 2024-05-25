#include <string.h>
#include "testbase.h"
#include "dsl.h"


void test_parse_int() {
    char* input = "123";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_int_expr(p->this_tok->literal);

    EXPECT_EQ_INT(123, n->integer);    
}

void test_parse_int_expr() {
    char* input = "123";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);

    EXPECT_EQ_INT(123, n->integer);
}

void test_parse_add_expr() {
    char* input = "1+2";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);

    EXPECT_EQ_INT(NODE_INFIX_EXPR, n->type);
    EXPECT_EQ_INT(1, n->infix_expr.left->integer);
    EXPECT_EQ_INT(OP_ADD, n->infix_expr.op);
    EXPECT_EQ_INT(2, n->infix_expr.right->integer);
}

void test_parse_mul_expr() {
    char* input = "1 * 2";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);

    EXPECT_EQ_INT(NODE_INFIX_EXPR, n->type);
    EXPECT_EQ_INT(OP_MUL, n->infix_expr.op);    
    EXPECT_EQ_INT(1, n->infix_expr.left->integer);
    EXPECT_EQ_INT(2, n->infix_expr.right->integer);
}


void test_parse_seq_expr() {
    char* input = "1 + 2 + 2;";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);

    EXPECT_EQ_INT(NODE_INFIX_EXPR, n->type);
    EXPECT_EQ_INT(1, n->infix_expr.left->infix_expr.left->integer);
    EXPECT_EQ_INT(2, n->infix_expr.left->infix_expr.right->integer);
    EXPECT_EQ_INT(OP_ADD, n->infix_expr.op);
    EXPECT_EQ_INT(2, n->infix_expr.right->integer);
}


void test_parse_let_stmts() {
    char* input = "let a = 1;";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_let_stmts(p);

    if (n == NULL) {
        printf("%s", "not match");
    }

    EXPECT_EQ_STR("a", n->name);
}

void test_parse_program() {
    char* input = "let pid =1; let b =1; let c =1; let d =1;";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* s = parse_program(p);

    EXPECT_EQ_STR("pid", s->name);
    EXPECT_EQ_STR("b", s->next->name);
    EXPECT_EQ_STR("c", s->next->next->name);
    EXPECT_EQ_STR("d", s->next->next->next->name);
}


void test_parse_block_stmts() {
    char* input = "{let a = 1; let b = 2; let c = 3;}";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_block_stmts(p);

    EXPECT_EQ_INT(NODE_LET, n->type);
    EXPECT_EQ_STR("a", n->name);

    EXPECT_EQ_INT(NODE_LET, n->type);
    EXPECT_EQ_STR("b", n->next->name);
    
    EXPECT_EQ_STR("c", n->next->next->name);
}

void test_parse_fnunction_call() {
    char* input = "pid();";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);

    EXPECT_EQ_STR("pid", n->name);
}

void test_parse_function_prams() {
    char* input = "get(1, 2, 3)";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);

    EXPECT_EQ_STR("get", n->name);
    EXPECT_EQ_INT(1, n->call.args->integer);
    EXPECT_EQ_INT(2, n->call.args->next->integer);
    EXPECT_EQ_INT(3, n->call.args->next->next->integer);
}

void test_parse_str_params() {
   char* input = "print(\"%d\", 1)";
   lexer_t* l = lexer_init(input);
   parser_t* p = parser_init(l);
   node_t* n = parse_expr(p, LOWEST);

   EXPECT_EQ_STR("print", n->name);
   EXPECT_EQ_STR("%d", n->call.args->name);
   EXPECT_EQ_INT(1, n->call.args->next->integer);
}

void test_parse_call_expr() {
    char* input = "pid(1, 2, 3)";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);

    EXPECT_EQ_STR("pid", n->name);
    EXPECT_EQ_INT(1, n->call.args->integer);
}


void test_prase_probe() {
    char* input = "probe sys:execute{ let a = 1; let b = 1;}";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_probe(p);

    if (n == NULL) {
        printf("not match\n");
    }

    EXPECT_EQ_STR("execute", n->probe.ident->name);
    EXPECT_EQ_STR("a", n->probe.stmts->name);
    EXPECT_EQ_STR("b", n->probe.stmts->next->name);
}

void test_parse_assign_expr() {
    char* input = "a = 1;";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);

    EXPECT_EQ_INT(OP_MOV, n->assign.op);
    EXPECT_EQ_INT(1, n->assign.expr->integer);
    EXPECT_EQ_STR("a", n->assign.lval->name);
}

void test_parse_assign_right_expr() {
    char* input = "a = 1+2";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);

    EXPECT_EQ_INT(OP_MOV, n->assign.op);
    EXPECT_EQ_INT(OP_ADD, n->assign.expr->infix_expr.op);
}

void test_parse_probe_all() {
    char* input = "probe sys:execute { print(\"%d\", pid()); }";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_program(p);

    EXPECT_EQ_STR("execute", n->probe.ident->name);
    EXPECT_EQ_STR("print", n->probe.stmts->name);
    EXPECT_EQ_STR("%d", n->probe.stmts->call.args->name);
    EXPECT_EQ_STR("pid", n->probe.stmts->call.args->next->name);
}

void test_new_let_stmts() {
    char* input = "let pid = 1;";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* s = parse_program(p);

    EXPECT_EQ_STR("pid", s->name);
    EXPECT_EQ_INT(1, s->let_stmts.expr->integer);
}

void test_parse_map() {
    char* input = "execute[1, pid()];";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);
    
    EXPECT_EQ_INT(NODE_MAP, n->type);    
    EXPECT_EQ_STR("execute", n->name);
    EXPECT_EQ_INT(1, n->map.args->integer);
    EXPECT_EQ_STR("pid", n->map.args->next->name ); 
}


void test_parse_map_assign() {
    char* input = "execute[pid(), comm()] = 1;";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);
    EXPECT_EQ_INT(NODE_ASSIGN, n->type);
    EXPECT_EQ_STR("execute", n->assign.lval->name);
    EXPECT_EQ_STR("pid", n->assign.lval->map.args->name);
    EXPECT_EQ_STR("comm", n->assign.lval->map.args->next->name);
    EXPECT_EQ_INT(1, n->assign.expr->integer);
    
    ebpf_t* e = ebpf_new();
    e->st = symtable_new();
    
    get_annot(n->assign.expr, e);
    get_annot(n, e);
    
    EXPECT_EQ_INT(16, n->assign.lval->annot.keysize);
    EXPECT_EQ_INT(8, n->assign.lval->annot.size);

    int fd = bpf_map_create(BPF_MAP_TYPE_HASH, n->assign.lval->annot.keysize, n->assign.lval->annot.size, 1024);
    printf("%d\n", fd);
}


void test_parse_eq_expr() {
    char* input = "/comm() == \"zsh\"/";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_probe_pred(p);
   
    EXPECT_EQ_STR("comm", n->pred.left->name);
    EXPECT_EQ_STR("zsh", n->pred.right->name); 
}

void test_parse_probe_pred() {
    char* input = "probe sys:execute/a == 1/ { c = 2;}";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_probe(p);

    EXPECT_EQ_STR("a", n->next->infix_expr.left->name);
    EXPECT_EQ_INT(1, n->next->infix_expr.right->integer);

    EXPECT_EQ_STR("c", n->probe.stmts->assign.lval->name);
    
}


int main() {
    //test_parse_eq_expr();
    test_parse_probe_pred();
    
    PRINT_ANS();
    return 0;
}




/*
int main() {
    test_parse_map_assign();
    test_parse_map();
    test_parse_assign_right_expr();
    test_parse_assign_expr();
    test_parse_probe_all();
    test_parse_call_expr();
    test_parse_str_params();
    test_parse_function_prams();
    test_parse_fnunction_call();
    test_prase_probe();
    test_parse_block_stmts();
    test_parse_mul_expr();
    test_parse_seq_expr();
    test_parse_add_expr(); 
    test_parse_int_expr();
    test_parse_int();
    test_parse_let_stmts();
    test_parse_program();
    PRINT_ANS();
}
*/
