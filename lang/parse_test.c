#include <string.h>
#include "testbase.h"
#include "dsl.h"

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
    EXPECT_EQ_INT(OP_ADD, n->infix_expr.opcode);
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
    EXPECT_EQ_INT(OP_ADD, n->infix_expr.opcode);
    EXPECT_EQ_INT(2, n->infix_expr.right->integer);
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
    EXPECT_EQ_INT(OP_ADD, n->assign.expr->infix_expr.opcode);
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
    //EXPECT_EQ_INT(1, s->let_stmts.expr->integer);
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



void test_parse_probe_pred() {
    char* input = "probe sys:execute/a == 1/ { c = 2;}";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_probe(p);

    EXPECT_EQ_STR("a", n->next->infix_expr.left->name);
    EXPECT_EQ_INT(1, n->next->infix_expr.right->integer);

    EXPECT_EQ_STR("c", n->probe.stmts->assign.lval->name);
    
}


void test_parse_comm() {
    char* input = "probe sys:execute/comm() == \"zsh\"/ { printf(\"Yes\");}";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_probe(p);

    
    EXPECT_EQ_STR("comm", n->next->infix_expr.left->name);
    EXPECT_EQ_STR("zsh", n->next->infix_expr.right->name);
}


void test_parse_var() {
    char* input = "c = 1;";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);
    EXPECT_EQ_STR("c", n->assign.lval->name);
}

void test_parse_probe() {
    char* input = "probe sys_enter/comm() == 1 /{ a = 1;}";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_probe(p);
    EXPECT_EQ_STR("sys_enter", n->probe.name);
    EXPECT_EQ_STR("comm", n->prev->infix_expr.left->name);
    EXPECT_EQ_INT(JUMP_JEQ, n->prev->infix_expr.opcode);
}


/*
int main() {
    test_parse_probe();
    PRINT_ANS();
    return 0;
}
*/
