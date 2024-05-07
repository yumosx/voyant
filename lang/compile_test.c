#include "testbase.h"
#include "dsl.h"
#include <string.h>

void test_program() {
    char* input = "probe sys:execute{ print(\"pid: %d\", pid());}";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_program(p);

    EXPECT_EQ_STR("execute", n->probe.ident->name);
    int id = get_tracepoint_id(n->probe.ident->name);
    EXPECT_EQ_INT(711, id);

    ebpf_t* e = ebpf_new();
    EXPECT_EQ_INT(NODE_CALL, n->probe.stmts->type);
    EXPECT_EQ_STR("print", n->probe.stmts->name);

    EXPECT_EQ_INT(NODE_STRING, n->probe.stmts->call.args->type);
    EXPECT_EQ_STR("pid: %d", n->probe.stmts->call.args->name);
    
    get_annot(n->probe.stmts->call.args, e);
    compile_str(e, n->probe.stmts->call.args);
    
    EXPECT_EQ_STR("pid", n->probe.stmts->call.args->next->name);
    EXPECT_EQ_INT(NODE_CALL, n->probe.stmts->call.args->next->type); 
    compile_call_(n->probe.stmts->call.args->next, e);
    compile_call_(n->probe.stmts, e);
    
    tracepoint_setup(e, 595);
}

void test_sym() {
    char* input = "a = pid()";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);
    symtable_t* s = symtable_new();
    ebpf_t* e = ebpf_new();
    e->st = s;

    EXPECT_EQ_STR("a", n->assign.lval->name);
    EXPECT_EQ_INT(OP_MOV, n->assign.op);
    EXPECT_EQ_STR("pid", n->assign.expr->name);

    symtable_transfer(e->st, n->assign.expr); 
    
    n->assign.lval->annot.type = n->assign.expr->annot.type;
    n->assign.lval->annot.size = n->assign.expr->annot.size;
    
    EXPECT_EQ_INT(NODE_INT, n->assign.expr->annot.type);    
    
    symtable_add(e->st, n->assign.lval);
    
    compile_call_(n->assign.expr, e);
    
    reg_t* dst = ebpf_reg_get(e); 
    
    ebpf_reg_load(e, dst, n->assign.expr);
    ebpf_reg_bind(e, dst, n->assign.lval); 
    
    input = "print(\"pid:%d\", a);";
    l = lexer_init(input);
    p = parser_init(l);
    node_t* n1 = parse_expr(p, LOWEST);
    
    EXPECT_EQ_STR("pid:%d", n1->call.args->name);
    EXPECT_EQ_STR("a", n1->call.args->next->name);
    
    get_annot(n1->call.args, e);
    compile_str(e, n1->call.args);
    compile_call_(n1, e);

    tracepoint_setup(e, 595);
}

int main() {
    test_sym();
    //test_program();
    PRINT_ANS();
    return 0;
}
