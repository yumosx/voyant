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

void test_node_iter() {
    char* input = "probe sys:execute{ a = \"a\"; print(\"pid: %s\", a);}";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_program(p);
    ebpf_t* e = ebpf_new();
    e->st = symtable_new();
    node_walk(n, e);
    tracepoint_setup(e, 595); 
}


void test_node() {
    char* input = "execute[pid()] = 2;";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);    
    ebpf_t* e = ebpf_new();
    e->st = symtable_new();
    
    EXPECT_EQ_INT(NODE_ASSIGN, n->type);
    EXPECT_EQ_STR("execute", n->assign.lval->name);
    EXPECT_EQ_STR("pid", n->assign.lval->map.args->name);
    
    EXPECT_EQ_INT(NODE_MAP, n->assign.lval->type);
    
    get_annot(n->assign.expr, e);    
    annot_map(n, e);
    
    EXPECT_EQ_INT(n->assign.lval->annot.size, 8);
    EXPECT_EQ_INT(n->assign.lval->annot.keysize, 8);
    
    int fd = bpf_map_create(BPF_MAP_TYPE_HASH, n->assign.lval->annot.keysize, n->assign.lval->annot.size, 1024);
    n->assign.lval->annot.mapid = fd;
    
    compile_call_(n->assign.lval->map.args, e);
    compile_map_assign(n, e);
    //compile_map_load(n->assign.lval, e);       
    
    input = "print(\"%d\", execute[pid()]);";
    l = lexer_init(input);
    p = parser_init(l);
    node_t* n1 = parse_expr(p, LOWEST);
    get_annot(n1->call.args, e);
    
    EXPECT_EQ_STR("print", n1->name);    
    EXPECT_EQ_STR("execute", n1->call.args->next->name); 
        
    get_annot(n1->call.args->name, e);
    compile_str(e, n1->call.args);
    compile_map_load(n->assign.lval, e); 
    ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_10));
    ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_1, n1->call.args->annot.addr));
    ebpf_emit(e, MOV_IMM(BPF_REG_2, strlen(n1->call.args->name) + 1));   
    ebpf_emit(e, LDXDW(BPF_REG_3, n->assign.lval->annot.addr, BPF_REG_10));    
    ebpf_emit(e, CALL(BPF_FUNC_trace_printk));

    ebpf_reg_bind(e, &e->st->reg[BPF_REG_0], n);
    ebpf_emit(e, EXIT);
        
    tracepoint_setup(e, 595);

}

void test_node_map() {
    char* input = "execute[pid()] = 2;";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_expr(p, LOWEST);    
    ebpf_t* e = ebpf_new();
    e->st = symtable_new();
    
    get_annot(n, e);
    EXPECT_EQ_INT(8, n->assign.lval->annot.size);
    EXPECT_EQ_INT(8, n->assign.lval->annot.keysize);
    
    int fd = bpf_map_create(BPF_MAP_TYPE_HASH, n->assign.lval->annot.keysize, n->assign.lval->annot.size, 1024);
    n->assign.lval->annot.mapid = fd;

    compile_call_(n->assign.lval->map.args, e);
    compile_map_assign(n, e);

    input = "print(\"%d\", execute[pid()]);";
    l = lexer_init(input);
    p = parser_init(l);
    node_t* n1 = parse_expr(p, LOWEST);
    
    get_annot(n1->call.args, e);
    
    EXPECT_EQ_INT(NODE_STRING, n1->call.args->annot.type);
    EXPECT_EQ_INT(LOC_STACK, n1->call.args->annot.loc);
    
    //TODO: like variable     
    n1->call.args->next = n->assign.lval;

    compile_str(e, n1->call.args);
    compile_map_load(n1->call.args->next, e);
    EXPECT_EQ_INT(NODE_INT, n1->call.args->next->annot.type);    
    EXPECT_EQ_INT(LOC_STACK, n1->call.args->next->annot.loc);
    
    compile_print(n1, e);
    
    ebpf_reg_bind(e, &e->st->reg[BPF_REG_0], n);
    ebpf_emit(e, EXIT);

    tracepoint_setup(e, 595);
}

/*
0. create the map
1. compile the map
2. compile the map index
*/

void test_node_map_2() {
    char* input = "probe sys:execute{ a = \"wyz\"; printf(\"%s\", a);}";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_program(p);
    ebpf_t* e = ebpf_new();
    e->st = symtable_new();
    node_walk(n, e);
    ebpf_reg_bind(e, &e->st->reg[BPF_REG_0], n);
    ebpf_emit(e, EXIT);

   
    tracepoint_setup(e, 595);    
}



void test_node_pred() {
    char* input = "probe execute{ printf(\"%s\", comm());}";
    lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_program(p);
    ebpf_t* e = ebpf_new();
    e->st = symtable_new();

    node_walk(n, e);
    ebpf_reg_bind(e, &e->st->reg[BPF_REG_0], n);
    ebpf_emit(e, EXIT);
    
    tracepoint_setup(e, 595);    
}

int main() {
    test_node_pred();
    //test_node_map();
    //test_node();
    //test_node_iter();
    //test_sym();
    //test_program();
    PRINT_ANS();
    return 0;
}
