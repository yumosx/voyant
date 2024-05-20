#include <unistd.h>
#include <ctype.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/perf_event.h>

#include "dsl.h"
#include "tracepoint.h"

char bpf_log_buf[LOG_BUF_SIZE];

static const char* node_type_str[] = {
    "TYE_SCRIPT",
    "TYPE_PROBE",
    "TYPE_EXPR",
    "TYPE_VAR",
    "TYPE_MAP",
    "TYPE_LET",
    "TYPE_ASSIGN",
    "TYPE_CALL",
    "TYPE_STRING",
    "TYPE_INT"
};

static const char* mode_str[] = {
    "PROBE_USER",
    "PROBE_SYS"
};

void p_next_tok(parser_t* p) {    
    p->this_tok = p->next_tok;
    p->next_tok = lexer_next_token(p->lexer);
}

parser_t* parser_init(lexer_t* l) {
    parser_t* p = malloc(sizeof(*p));

    if (p == NULL) {
        err(EXIT_FAILURE, "parser malloc failed");
    }
    
    p->lexer = l;
    p->this_tok = NULL;
    p->next_tok = NULL;

    p_next_tok(p);
    p_next_tok(p);

    return p;
}


int this_tok_is(parser_t* p, token_type type) {
    return p->this_tok->type == type;
}

int next_tok_is(parser_t* p, token_type type) {
    return p->next_tok->type == type;
}

int expect_peek(parser_t* p, token_type t) {
    if (next_tok_is(p, t)) {
        p_next_tok(p);
        return 1;
    } else {
        return 0;
    }
}

node_t* node_new(node_type_t t) {
    node_t* n = malloc(sizeof(*n));

    if (n == NULL) {
       err(EXIT_FAILURE, "malloc failure");
    }

    n->type = t;
    return n;
}

node_t* int_new(int64_t val) {
    node_t* n = node_new(NODE_INT);
    n->integer = val;
    return n;
}


node_t* node_new_var(char* name) {
    node_t* n = node_new(NODE_VAR);
    n->name = name;
    return n;
}

node_t* node_new_let(char* name) {
    node_t* n = node_new(NODE_LET);
    n->name = name;
    return n;
}

node_t* node_int_new(char* value) {
    node_t* n = node_new(NODE_INT);
    n->name = value;
    return n;
}

node_t* node_str_new(char* str) {
    node_t* n = node_new(NODE_STRING);
    n->name = str;
    return n;
}

static seq_t get_token_seq(token_type t) {
    switch (t) {
    case TOKEN_PLUS:
        return SUM;
        break;
    case TOKEN_STAR:
        return PRODUCT;
        break;
    case LEFT_PAREN:
        return CALL;
        break;
    case TOKEN_LEFT_BRACKET:
        return INDEX;
        break;
    case TOKEN_ASSIGN:
        return ASSIGN;
        break;
    default:
        return LOWEST;
        break;
    }
}

node_t* parse_int_expr(char* name) {
    node_t* expr = node_new(NODE_INT);
    expr->integer = 0;

    char* s = name;

    while (*s != '\0') {
        expr->integer = (expr->integer * 10) + (*s++ - '0');
    }
    
    return expr;
}

op_t get_op(token_type t) {
    switch (t)
    {
    case TOKEN_ASSIGN:
        return OP_MOV;

    case TOKEN_STAR:
        return OP_MUL;

    case TOKEN_PLUS:
        return OP_ADD;
    default:
        break;
    }
}

node_t* parse_infix_expr(parser_t* p, node_t* left) {
    node_t* n = node_new(NODE_INFIX_EXPR);
    n->infix_expr.left = left;
    n->infix_expr.op = get_op(p->this_tok->type);
    seq_t seq = get_token_seq(p->this_tok->type);
    p_next_tok(p);
    n->infix_expr.right = parse_expr(p, seq);
    
    return n; 
}

node_t* parse_call_args(parser_t* p) {
    node_t* n, *head;
    
    if (next_tok_is(p, RIGHT_PAREN)) {
        p_next_tok(p);
        return NULL;
    }
    
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
        return NULL;
    }

    return head;
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
        return NULL;
    }

    return head;
}


node_t* parse_call_expr(parser_t* p, node_t* left) {
    left->type = NODE_CALL;
    left->call.args = parse_call_args(p);
    return left;
}


node_t* parse_assign_expr(parser_t* p, node_t* left) {
    //if (left->type != NODE_VAR || left->type != NODE_MAP) {
    //    err(EXIT_FAILURE, "Parsing error: invalid assigment left-hand side");
    //}

    node_t* n = node_new(NODE_ASSIGN);

    n->assign.op = OP_MOV;
    n->assign.lval = left;
    int seq = get_token_seq(p->this_tok->type);
    p_next_tok(p);
    n->assign.expr = parse_expr(p, seq); 
    return n;
}

node_t* parse_map_expr(parser_t* p, node_t* left) {
    left->type = NODE_MAP;
    p_next_tok(p);
    left->map.args = parse_map_args(p);
    return left;
}

node_t* parse_expr(parser_t* p, seq_t s) {    
    node_t* left;

    switch (p->this_tok->type) {
        case TOKEN_INT:
            left = parse_int_expr(p->this_tok->literal);
            break;
        case TOKEN_IDENT:
            left = node_new_var(p->this_tok->literal);
            break;
        case TOKEN_STRING:
            left = node_str_new(p->this_tok->literal);
            break;
        default:
            return NULL;
    }
    
    while (!next_tok_is(p, TOKEN_SEMICOLON) && s < get_token_seq(p->next_tok->type)) {
        switch (p->next_tok->type) {
        case TOKEN_ASSIGN:
            p_next_tok(p);
            left = parse_assign_expr(p, left);
            break;
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
        default:
            break;
        }
    
    }

    return left;
}


node_t* parse_let_stmts(parser_t* p) {
    node_t* n;
    
    if (!expect_peek(p, TOKEN_IDENT)) {
       return NULL; 
    }
    
    n = node_new_let(p->this_tok->literal);

    if (!expect_peek(p, TOKEN_ASSIGN)) {
        return NULL;
    }

    while (!this_tok_is(p, TOKEN_SEMICOLON)) {
        p_next_tok(p);
    }

    free_token(p->this_tok);

    return n;
}


node_t* parse_stmts(parser_t* p) {
    switch (p->this_tok->type) {
    case TOKEN_LET:
        return parse_let_stmts(p);    
    default:
        return parse_expr(p, LOWEST);
    }
}


node_t* parse_block_stmts(parser_t* p) {
    node_t* n, *head;
    p_next_tok(p);
    n = parse_stmts(p);
    
    head = n;
    
    p_next_tok(p);
    
    while (!next_tok_is(p, TOKEN_RIGHT_BLOCK) && !next_tok_is(p, END_OF_FILE)) {
        node_t* stmts = parse_stmts(p);

        if (stmts != NULL) {
            n->next = stmts;
            n = n->next;
        }

        p_next_tok(p);
    }

    return head;
}


node_t* parse_probe(parser_t* p) {
    node_t* node = node_new(NODE_PROBE);

    if (!expect_peek(p, TOKEN_IDENT)) {
        free(node);
        return NULL;
    }

    if (strcmp(p->this_tok->literal, "sys") == 0) {
        node->probe.mode = PROBE_SYS;
        free_token(p->this_tok);
    }

    if (!expect_peek(p, TOKEN_COLON)) {
       free(node);
       return NULL;
    }
    
    if (!expect_peek(p, TOKEN_IDENT)) {
        free(node);
        return NULL;
    }
    
    node->probe.ident = node_new_var(p->this_tok->literal);
    p_next_tok(p); 
    node->probe.stmts = parse_block_stmts(p); 

    return node;
}


node_t* parse_program(parser_t* p) {
    node_t* n, *head;

    if (p->this_tok->type != END_OF_FILE) {
        switch (p->this_tok->type)
        {
        case TOKEN_LET:
            n = parse_let_stmts(p);
            p_next_tok(p);
            break;
        case TOKEN_PROBE:
            n = parse_probe(p);
            p_next_tok(p);
            break;
        default:
            break;
        }
    }
    
    head = n;
   

    while (p->this_tok->type != END_OF_FILE) {
        if (p->this_tok->type == TOKEN_LET) {
            n->next = parse_let_stmts(p);
            p_next_tok(p);
            n = n->next;
        } else if (p->this_tok->type == TOKEN_PROBE) {
            n->next = parse_probe(p);
            p_next_tok(p);
            n = n->next;
        } else {
            return head;
        }
    }

    return head;
}

static void sym_init(symtable_t* st) {
    sym_t* sym;

    sym = &st->table[st->len++];
    sym->annot.type = NODE_INT;
    sym->annot.size = 8;
    sym->name = "@$";
    sym->size = sym->annot.size;
}


symtable_t* symtable_new() {
    symtable_t* st;
    int i;

    st = malloc(sizeof(*st));

    if (st == NULL) {
        err(EXIT_FAILURE, "malloc failure");
    }

    st->cap = 16;
    st->table = calloc(st->cap, sizeof(*st->table));
     
    sym_init(st);

    for ( i = BPF_REG_0; i < __MAX_BPF_REG; i++ ) {
        *(int*)(&st->reg[i].reg) = i;
    }

    return st;
}


ssize_t symtable_reserve(symtable_t* st, size_t size) {
    st->stack_top -= size;
    return st->stack_top;
}


sym_t* symtable_get(symtable_t* st, const char* name) {
    size_t i;

    for (i = 0; i < st->len; i++) {
        if (!strcmp(st->table[i].name, name)) {
            return &st->table[i]; 
        }
    }

    return NULL;
}


int symtable_transfer(symtable_t* st, node_t* n) {
    sym_t* sym;
    
    if ( n->type != NODE_VAR ) {
        return 0;
    }
    
    sym = symtable_get(st, n->name);

    n->annot = sym->annot;

    return 0;
}

int symtable_map_transfer(symtable_t* st, node_t* m) {
    node_t* n, *head = m->map.args;
    
    for (n = head; n != NULL; n = n->next) {
        symtable_transfer(st, n);
    }    
    
    return 0; 
}

void symtable_add(struct symtable_t* st, node_t* n) {
   sym_t* sym;
    //TODO: if define 
   if ( st->len == st->cap ) {
        st->cap += 16;
        st->table = realloc(st->table, st->cap * sizeof(*st->table));
        memset(&st->table[st->len], 0, 16 * sizeof(*st->table));
   }
   
   sym = &st->table[st->len++];
   sym->name = n->name;
   sym->annot = n->annot;
   sym->size = n->annot.size; 
   
   if (n->type == NODE_MAP) {
      sym->size += n->annot.keysize;
   }
   sym->addr = symtable_reserve(st, sym->size);
}

ebpf_t* ebpf_new() {
    ebpf_t* e = calloc(1, sizeof(*e));
    
    if (e == NULL) {
        err(EXIT_FAILURE, "malloc failure");
    }
    
    e->st = symtable_new();     
    e->ip = e->prog;

    if (e->st == NULL) {
        err(EXIT_FAILURE, "malloc failure");
    }
    
    return e;
}


void ebpf_emit(ebpf_t* e, struct bpf_insn insn) {
    *(e->ip)++ = insn;
}

reg_t* ebpf_reg_find(ebpf_t* e, node_t* n) {
   reg_t* r;
   void* obj = n;
   int type = REG_NODE;

   if (n->type == NODE_VAR || n->type == NODE_MAP) {
        type = REG_SYM;
        obj = symtable_get(e->st, n->name);
   }

   for (r = &e->st->reg[BPF_REG_0]; r <= &e->st->reg[BPF_REG_9]; r++) {
        if (r->type == type && r->obj == obj)
                return r;
   }
}

void ebpf_reg_load(ebpf_t* e, reg_t* r, node_t* n) {    
    if (n->type == NODE_STRING) {
        r->type = REG_NODE;
        r->n = n; 
        ebpf_emit(e, MOV(r->reg, BPF_REG_10));
        ebpf_emit(e, ALU_IMM(OP_ADD, r->reg, n->annot.addr));
    } else if (n->type == NODE_INT) {
        r->type = REG_NODE;
        r->n = n;
        ebpf_emit(e, MOV_IMM(r->reg, n->integer));
    } else if (n->type == NODE_VAR || n->type == NODE_MAP){
        sym_t* sym;
        sym = symtable_get(e->st, n->name);
        
        if (sym->reg) {
            r->type = REG_NODE;
            r->n = n;
            ebpf_emit(e, MOV(r->reg, sym->reg->reg));
        } else {
            sym->reg = r;
            r->type = REG_SYM;
            r->sym = sym;
            ebpf_emit(e, LDXDW(r->reg, sym->addr, BPF_REG_10));
        }
        
    } else {
        reg_t* src;
        src = ebpf_reg_find(e, n);
        r->type = REG_NODE;
        r->n = n;
        ebpf_emit(e, MOV(r->reg, src->reg));        
    } 
}


void ebpf_push(ebpf_t* e, ssize_t at, void* data, size_t size) {
    
    uint32_t* wdata = data;
         
    size_t left = size / sizeof(*wdata);
    
    for (; left; left--, wdata++, at += sizeof(*wdata)) {
        ebpf_emit(e, STW_IMM(BPF_REG_10, at, *wdata));
    }
    
}


reg_t* ebpf_reg_get(ebpf_t* e) {
    reg_t* r, *r_aged = NULL;
    
    for (r = &e->st->reg[BPF_REG_9]; r >= &e->st->reg[BPF_REG_0]; r--) {
       if (r->type == REG_EMPTY) {
            return r;
       } 

       if (r->type == REG_SYM && (!r_aged || r->age < r_aged->age)) {
            r_aged = r;
       }
    }

}

void ebpf_reg_put(ebpf_t* e, reg_t* r) {
    if (!r)
        return;
}


void emit_ld_mapfd(ebpf_t* e, int reg, int fd) {
    ebpf_emit(e, INSN(BPF_LD|BPF_DW|BPF_IMM, reg, BPF_PSEUDO_MAP_FD, 0, fd));
    ebpf_emit(e, INSN(0, 0, 0, 0, 0));
}



static inline int node_is_sym(node_t* n) {
    return n->type == NODE_VAR || n->type == NODE_MAP;
}

int ebpf_reg_bind(ebpf_t* e, reg_t* r, node_t* n) {
    if (node_is_sym(n)) {
        sym_t* sym;
        sym = symtable_get(e->st, n->name);

       if (!sym)
            return -1;

        sym->reg = r;
        r->type = REG_SYM;
        r->sym = sym;
    } else {
        r->type = REG_NODE;
        r->n = n;
    }

    return 0;
}

void compile_call(ebpf_t* e, node_t* n) {
    node_t* args, *fmtlen;
     
    reg_t* r = e->st->reg;
    
    int reg;
    
    reg = BPF_REG_1;

    args = n->call.args;

    ebpf_reg_load(e, &r[reg++], args);

    fmtlen = node_new(NODE_INT);
        
    fmtlen->integer = strlen(args->name) + 1;

    ebpf_reg_load(e, &r[reg++], fmtlen);
    ebpf_reg_load(e, &r[reg++], args->next); 
    ebpf_emit(e, CALL(BPF_FUNC_trace_printk));
    ebpf_reg_bind(e, &e->st->reg[BPF_REG_0], n);
    ebpf_emit(e, EXIT);
}


int int32_void_func(enum bpf_func_id func, extract_op_t op, ebpf_t* e, node_t* n) {
    reg_t* dst;
    
    ebpf_emit(e, CALL(func));
    
    switch(op) {
        case EXTRACT_OP_MASK:
            ebpf_emit(e, ALU_IMM(OP_AND, BPF_REG_0, 0xffffffff));
            break;
        case EXTRACT_OP_SHIFT:
            ebpf_emit(e, ALU_IMM(OP_RSH, BPF_REG_0, 32));
            break;
        default:
            break;
    }

    dst = ebpf_reg_get(e); 
    
    if (!dst)
        err(EXIT_FAILURE, "malloc failed");
    
    ebpf_emit(e, MOV(dst->reg, 0));
    ebpf_reg_bind(e, dst, n);

    return 0; 
}


int compile_pid_call(ebpf_t* e, node_t* n) {
    return int32_void_func(BPF_FUNC_get_current_pid_tgid, EXTRACT_OP_MASK, e, n);
}

static int compile_ns_call(ebpf_t* e, node_t* n) {
    return int32_void_func(BPF_FUNC_ktime_get_ns, EXTRACT_OP_NONE, e, n);
}

static __u64 ptr_to_u64(const void* ptr) {
    return (__u64) (unsigned long) ptr;
}

int bpf_prog_load(const struct bpf_insn* insns, int insn_cnt) {
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_TRACEPOINT,
        .insns = ptr_to_u64(insns),
        .insn_cnt = insn_cnt,
        .license = ptr_to_u64("GPL"),
        .log_buf = ptr_to_u64(bpf_log_buf),
        .log_size = LOG_BUF_SIZE,
        .log_level = 1,
        .kern_version = LINUX_VERSION_CODE,
    };


    return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_map_create(enum bpf_map_type type, int key_sz, int val_sz, int entries) {
    union bpf_attr attr = {
       .map_type = type,
       .key_size = key_sz,
       .value_size = val_sz,
       .max_entries = entries,
    };

    return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}


int bpf_map_close(){
}

long perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    int ret;
    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
    return ret;    
}

#define DEBUGFS "/sys/kernal/debug/tracing"

void read_trace_pipe(void) {
    int trace_fd;
    trace_fd = open(DEBUGFS, "trace_pipe", O_RDONLY, 0);
    
    if (trace_fd < 0)
        printf("error"); 
    
    while (1) {
        static char buf[4096];
        ssize_t sz;
        
        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz > 0) {
            buf[sz] = 0;
            puts(buf);
        }
    }
}



int tracepoint_setup(ebpf_t* e, int id) {
    struct perf_event_attr attr = {};
    
    int ed, bd;

    attr.type = PERF_TYPE_TRACEPOINT;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.config = id;  
    
    bd = bpf_prog_load(e->prog, e->ip - e->prog);
    
    if (bd < 0) {
        perror("bpf");
        fprintf(stderr, "bpf verifier:\n%s\n", bpf_log_buf);
        return 1;
    }
    
    ed = perf_event_open(&attr, -1, 0, -1, 0);

    if (ed < 0){
        perror("perf_event_open");
        return 1;
    }
    
    if (ioctl(ed, PERF_EVENT_IOC_ENABLE, 0)) {
        perror("perf enable");
        return 1;
    }


    if (ioctl(ed, PERF_EVENT_IOC_SET_BPF, bd)) {
        perror("perf attach");
        return 1;
     } 
    
    
    //read_trace_pipe();        
        
 
    while (1) {
        system("cat /sys/kernel/debug/tracing/trace_pipe");
        getchar(); 
  
    }
    
    return 0;
}

void assign_assign(node_t* n, ebpf_t* e) {
    
}

void annot_map(node_t* n, ebpf_t* e) {
   symtable_transfer(e->st, n->assign.expr);
   
   n->assign.lval->annot.type = n->assign.expr->annot.type;
   n->assign.lval->annot.size = n->assign.expr->annot.size;
   
    if (n->assign.lval->type == NODE_MAP) {
        node_t* head, *args = n->assign.lval->map.args;
        ssize_t ksize = 0; 
        
        for (head = args; head != NULL; head = head->next) {
            get_annot(head, e);
            ksize += head->annot.size;
        }
        n->assign.lval->annot.keysize = ksize;
        n->assign.lval->annot.addr -= ksize + n->assign.lval->annot.size;
    }
    
   symtable_add(e->st, n->assign.lval);     
}

void get_annot(node_t* n, ebpf_t* e) {
     switch(n->type) {
        case NODE_INT:
            n->annot.type = NODE_INT;
            n->annot.size = sizeof(n->integer);
            break;
        case NODE_STRING:
            n->annot.type = NODE_STRING;
            n->annot.size = _ALIGNED(strlen(n->name) + 1);
            n->annot.addr = symtable_reserve(e->st, n->annot.size);
            break;
        case NODE_CALL:
            n->annot.type = NODE_INT;
            n->annot.size = 8;
            n->annot.reg = 0;
            break;
        case NODE_ASSIGN:
            annot_map(n, e);
            /*
            symtable_transfer(e->st, n->assign.expr);
            n->assign.lval->annot.type = n->assign.expr->annot.type;
            n->assign.lval->annot.size = n->assign.expr->annot.size;
            symtable_add(e->st, n->assign.lval);
            */
            break;
        default:
            break;
    }
}


void compile_str(ebpf_t* e, node_t* n) {
    ebpf_push(e, n->annot.addr, n->name, n->annot.size);
}


void compile_call_(node_t* n, ebpf_t* e) {
    if (!strcmp(n->name, "pid")) {
        compile_pid_call(e, n);
    } else if (!strcmp(n->name, "print")) {
        compile_call(e, n);
    } else {
        err(EXIT_FAILURE, "not match the function");
    }
}


void compile(node_t* n, ebpf_t* _e) {
    ebpf_t* e = _e;
    
    switch (n->type) {
       case NODE_STRING:
            compile_str(e, n);
            break;
       case NODE_CALL:
            compile_call(e, n);
            break;
    }
}


int get_tracepoint_id(char* name) {
    if (!strcmp(name, "execute")) {
        return 711;
    } else if (!strcmp(name, "socket")) {
        return 1439;
    } else if (!strcmp(name, "openat")) {
        return 633; 
    } else {
        err(EXIT_FAILURE, "do not have this trace id");
    }
}


void node_walk(node_t* n, ebpf_t* e);

void node_probe_walk(node_t* p, ebpf_t* e) {
    node_t* stmts = p->probe.stmts;
    node_t* n;
    
    for (n = stmts; n != NULL; n = n->next) {
        node_walk(n, e); 
    }
}

/*
void compile_map(node_t* a, ebpf_t* e) {
    int fd = bpf_map_create(BPF_MAP_TYPE_HASH, a->assign.lval->annot.keysize, a->assign.lval->annot.size, 1024);
    a->assign.expr->annot.mapid = fd;    
 
    compile_map_load(a->assign.expr, e);

    ebpf_emit(e, MOV(BPF_REG_2, BPF_REG_10));
    ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_2, a->assign.lval->annot.addr + a->assign.lval->annot.size));
        
    ebpf_emit(e, MOV(BPF_REG_3, BPF_REG_10));
    ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_3, a->assign.lval->annot.addr));
        
    ebpf_emit(e, MOV_IMM(BPF_REG_4, 0)); 
    ebpf_emit(e, CALL(BPF_FUNC_map_update_elem));
    ebpf_reg_bind(e, &e->st->reg[BPF_REG_0], a);
    ebpf_emit(e, EXIT);
}
*/


void compile_map_load(node_t* head, ebpf_t* e) {

    int at = head->annot.addr + head->annot.size; 
    
    //just has one args
    ebpf_emit(e, STXDW(BPF_REG_10, at, BPF_REG_0));

    emit_ld_mapfd(e, BPF_REG_1, head->annot.mapid);
    
    ebpf_emit(e, MOV(BPF_REG_2, BPF_REG_10));
    ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_2, head->annot.addr)); 
    ebpf_emit(e, CALL(BPF_FUNC_map_lookup_elem));
    
    ebpf_emit(e, JMP_IMM(JUMP_JEQ, BPF_REG_0, 0, 6));

    ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_10));
    ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_1, head->annot.addr));
    ebpf_emit(e, MOV_IMM(BPF_REG_2, head->annot.size));
    ebpf_emit(e, MOV(BPF_REG_3, BPF_REG_0));
    
    ebpf_emit(e, CALL(BPF_FUNC_probe_read));
    ebpf_emit(e, JMP_IMM(JUMP_JA, 0, 0, head->annot.size / 4));

    for (int i = 0; i < (ssize_t)head->annot.size; i += 4) {
        ebpf_emit(e, STW_IMM(BPF_REG_10, head->annot.addr + i, 0));
    }
}


void node_assign_walk(node_t* a, ebpf_t* e) {
    get_annot(a, e);
    
    node_t* expr = a->assign.expr;
    node_walk(expr, e);
   
    
    if (a->assign.lval->type == NODE_MAP) {
        int fd = bpf_map_create(BPF_MAP_TYPE_HASH, a->assign.lval->annot.keysize, a->assign.lval->annot.size, 1024);
        a->assign.lval->annot.mapid = fd;
        
        node_walk(a->assign.lval->map.args, e);

        //emit_ld_mapfd(e, BPF_REG_1, fd); 
        compile_map_load(a->assign.lval, e);

        ebpf_emit(e, MOV(BPF_REG_2, BPF_REG_10));
        ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_2, a->assign.lval->annot.addr + a->assign.lval->annot.size));
        
        ebpf_emit(e, MOV(BPF_REG_3, BPF_REG_10));
        ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_3, a->assign.lval->annot.addr));
        
        ebpf_emit(e, MOV_IMM(BPF_REG_4, 0)); 
        ebpf_emit(e, CALL(BPF_FUNC_map_update_elem));
        ebpf_reg_bind(e, &e->st->reg[BPF_REG_0], a);
        ebpf_emit(e, EXIT);
    } else {    
        reg_t* dst = ebpf_reg_get(e);
        ebpf_reg_load(e, dst, expr);
        ebpf_reg_bind(e, dst, a->assign.lval);
    }
}


void node_call_walk(node_t* c, ebpf_t* e) {
    node_t* args = c->call.args;
    node_t* n;
    
    for (n = args; n != NULL; n = n->next) {
        node_walk(n, e);
    }
    
    compile_call_(c, e);
}

void node_walk(node_t* n, ebpf_t* e) {
    switch(n->type) {
        case NODE_PROBE:
            node_probe_walk(n, e);
            break;
        case NODE_ASSIGN:
            node_assign_walk(n, e);  
            break;
        case NODE_CALL:
            node_call_walk(n, e);
            break;
        case NODE_INT:
            get_annot(n, e);
            break;
        case NODE_STRING:
            get_annot(n, e);
            compile_str(e, n);
            break;
        default:
            break;
    }
}


char* read_file(const char* filename) {
    char* input = calloc(BUFSIZ, sizeof(char));
    if (input != NULL) {
        err(EXIT_FAILURE, "malloc failed");            
    }

    uint32_t size = 0;

    FILE* f = fopen(filename, "r");
    
    if (!f) {
        err(EXIT_FAILURE, "open file error");
    }
    
    uint32_t read = 0;

    while ( (read = fread(input, sizeof(char), BUFSIZ, f)) > 0) {
        size += read;
       
        if (read > BUFSIZ) {
            input = (char*) realloc(input, size+BUFSIZ);
            if (input == NULL) {
                err(EXIT_FAILURE, "remalloc failed");
            }    
        }
    }

    input[size] = '\0';
    fclose(f);

    return input;
}
