#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/perf_event.h>

#include "dsl.h"
#include "buffer.h"
#include "annot.h"
#include "ut.h"
#include "compiler.h"


static inline 
int node_is_sym(node_t* n) {
    return n->type == NODE_VAR || n->type == NODE_MAP;
}

reg_t* ebpf_reg_find(ebpf_t* e, node_t* n) {
   reg_t* r;
   void* obj = n;
   int type = REG_NODE;

   if (node_is_sym(n)) {
        type = REG_SYM;
        obj = symtable_get(e->st, n->name);
   }

   for (r = &e->st->reg[BPF_REG_0]; r <= &e->st->reg[BPF_REG_9]; r++) {
        if (r->type == type && r->obj == obj) return r;
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

reg_t* ebpf_reg_get(ebpf_t* e) {
    reg_t* r, *r_aged = NULL;
    
    for (r = &e->st->reg[BPF_REG_8]; r >= &e->st->reg[BPF_REG_0]; r--) {
       if (r->type == REG_EMPTY) {
            return r;
       } 

       if (r->type == REG_SYM && (!r_aged || r->age < r_aged->age)) {
            r_aged = r;
       }
    }
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


/*
1. pid() -> reg0 -> reg2
2. map value -> stack
3. "sss" -> stack
*/
void generic_load_args(node_t* arg, ebpf_t* e, int* reg) {
    switch (arg->annot.type) {
    case NODE_INT:
        if (arg->annot.loc == LOC_STACK){
           ebpf_emit(e, LDXDW(*reg, arg->annot.addr, BPF_REG_10));
        } else {
			//ebpf_emit(e, MOV(*reg, ebpf_reg_find(e, arg)->reg)); 
			ebpf_emit(e, MOV_IMM(*reg, arg->integer));
        }
        break;                  
    case NODE_STRING:
        if (arg->type == NODE_CALL) {
            ebpf_emit(e, MOV(*reg, BPF_REG_10));
            ebpf_emit(e, ALU_IMM(OP_ADD, *reg, arg->annot.addr));
            return;
        }

        compile_str(e, arg);
        ebpf_emit(e,  MOV(*reg, BPF_REG_10));
        ebpf_emit(e, ALU_IMM(OP_ADD, *reg, arg->annot.addr));
        (*reg)++;
        
        //if (arg->type == NODE_CALL) {
        //    break;
        //}
        ebpf_emit(e, MOV_IMM(*reg, strlen(arg->name) + 1)); 
        break;
    default:
		ebpf_emit(e, MOV(*reg, ebpf_reg_find(e, arg)->reg)); 
		break;
    }
}


void compile_print(node_t* n, ebpf_t* e) {
    node_t* head;
    int reg = BPF_REG_1;
       
    for (head = n->call.args; head != NULL; head = head->next) {
        generic_load_args(head, e, &reg);
        reg++;
    }

    ebpf_emit(e, CALL(BPF_FUNC_trace_printk));
}


/*
void compile_comm(node_t* n, ebpf_t* e) {
    size_t i;
    
    for (i = 0; i < n->annot.size; i += 4) {
        ebpf_emit(e, STW_IMM(BPF_REG_10, n->annot.addr + i, 0));
    }
    
    ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_10));
    ebpf_emit(e, ALU_IMM(OP_ADD, BPF_REG_1, n->annot.addr));
    ebpf_emit(e, MOV_IMM(BPF_REG_2, n->annot.size));
    ebpf_emit(e, CALL(BPF_FUNC_get_current_comm));
}
*/


void compile_pred(ebpf_t* e, node_t* n) {
   node_t* s1 = n->infix_expr.left, *s2 = n->infix_expr.right;
   ssize_t i, l;
   l = s1->annot.size < s2->annot.size ? s1->annot.size : s2->annot.size;
   
    for (i = 0; l; i++, l--) {
		ebpf_emit(e, LDXB(BPF_REG_0, s1->annot.addr + i, BPF_REG_10));
		ebpf_emit(e, LDXB(BPF_REG_1, s2->annot.addr + i, BPF_REG_10));
        
		ebpf_emit(e, ALU(OP_SUB, BPF_REG_0, BPF_REG_1));
		
        if (l==1)
            break;

        ebpf_emit(e, JMP_IMM(JUMP_JEQ, BPF_REG_1, 0, 5 * (l - 2) + 4));
		ebpf_emit(e, JMP_IMM(JUMP_JNE, BPF_REG_0, 0, 5 * (l - 2) + 3));
	}
 
    ebpf_emit(e, JMP_IMM(JUMP_JEQ, BPF_REG_0, 0, 2));
    ebpf_emit(e, MOV_IMM(BPF_REG_0, 0));
    ebpf_emit(e, EXIT);
}


int int32_void_func(enum bpf_func_id func, extract_op_t op, ebpf_t* e, node_t* n) {
    reg_t* dst;
    n->annot.type = LOC_REG;
    
    ebpf_emit(e, CALL(func));
    
    switch(op) {
        case EXTRACT_OP_MASK:
            ebpf_emit(e, ALU_IMM(OP_AND, BPF_REG_0, 0xffffffff));
            break;
        case EXTRACT_OP_SHIFT:
            ebpf_emit(e, ALU_IMM(OP_RSH, BPF_REG_0, 32));
            break;
		case EXTRACT_OP_DIV_1G:
			ebpf_emit(e, ALU_IMM(OP_DIV, BPF_REG_0, 1000000000));
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
    return int32_void_func(BPF_FUNC_ktime_get_ns, EXTRACT_OP_DIV_1G, e, n);
}

static int compile_cpu_call(ebpf_t* e, node_t* n) {
	return int32_void_func(BPF_FUNC_get_smp_processor_id, EXTRACT_OP_NONE, e, n);
}

static __u64 ptr_to_u64(const void* ptr) {
    return (__u64) (unsigned long) ptr;
}

#define DEBUGFS "/sys/kernal/debug/tracing"

void read_trace_pipe(void) {
    int trace_fd;
    trace_fd = open(DEBUGFS, "trace_pipe", O_RDONLY, 0);
    
    if (trace_fd < 0)
        _errno("trace fd not found");

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

int get_id(char* name) {
    char* buffer; 
    FILE* fp;   
    int number;

    buffer = checked_malloc(256); 
    sprintf(buffer, "/sys/kernel/debug/tracing/events/syscalls/%s/id", name);

    fp = fopen(buffer, "r");
    
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }

    if (fscanf(fp, "%d", &number) != 1) {
        fprintf(stderr, "Error reading number from file\n");
        fclose(fp);
        return 1;
    }
    free(buffer);
    return number;
}

void compile_str(ebpf_t* e, node_t* n) {
    str_to_stack(e, n->annot.addr, n->name, n->annot.size);
}

void compile_call(node_t* n, ebpf_t* e) {
    if (!strcmp(n->name, "pid")) {
        compile_pid_call(e, n);
    } else if (!strcmp(n->name, "printf")) {
        compile_print(n, e);
    } else if (!strcmp(n->name, "comm")) {
        compile_comm(n, e);
    } else if (!strcmp(n->name, "ns")) {
	    compile_ns_call(e, n);
	} else if (!strcmp(n->name, "cpu")) {
		compile_cpu_call(e, n);
    } else if (!strcmp(n->name, "out")) {
		node_t* rec = n->call.args->next;
		compile_out(rec, e); 
    } else {
        _errno("no matach function");
	}
}

void node_walk(node_t* n, ebpf_t* e);

void node_probe_walk(node_t* p, ebpf_t* e) {
    int id = get_id(p->probe.name);
    p->probe.traceid = id;    
    
    printf("attach the [%s] id:[%d]\n", p->probe.name, id);    
    
    if (p->prev) {
        node_t* n1 = p->prev->infix_expr.left, *n2 = p->prev->infix_expr.right;
        node_walk(n1, e);
        node_walk(n2, e);
        compile_pred(e, p->prev);
    }

    node_t* stmts = p->probe.stmts;
    node_t* n;
 
    for (n = stmts; n != NULL; n = n->next) {
		node_walk(n, e); 
    }
}


void compile_map_load(node_t* head, ebpf_t* e) {
	sym_t* sym = symtable_get(e->st, head->name);    

    head->annot = sym->annot;

    int at = head->annot.addr + head->annot.size; 
    
    //TODO: just has one args
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
    //ebpf_emit(e, JMP_IMM(JUMP_JA, 0, 0, head->annot.size / 4));

    for (int i = 0; i < (ssize_t)head->annot.size; i += 4) {
        ebpf_emit(e, STW_IMM(BPF_REG_10, head->annot.addr + i, 0));
    }

    head->annot.loc = LOC_STACK;
}


void node_assign_walk(node_t* a, ebpf_t* e) {
    node_t* expr = a->assign.expr;
    
    get_annot(a, e);
    node_walk(expr, e);
    
    if (a->assign.lval->type == NODE_MAP) {
        compile_map_assign(a, e);
    } else {    
        reg_t* dst = ebpf_reg_get(e);
        //TODO: the bug of get the call        
        if (expr->type == NODE_CALL && expr->annot.type == NODE_STRING) {
            dst->type = REG_NODE;
            dst->n = expr; 
            ebpf_emit(e, MOV(dst->reg, BPF_REG_10));
            ebpf_emit(e, ALU_IMM(OP_ADD, dst->reg, expr->annot.addr));
            
            ebpf_reg_bind(e, dst, expr);
            return;
        }
        ebpf_reg_load(e, dst, expr);
        ebpf_reg_bind(e, dst, a->assign.lval);
    }
}

void node_call_walk(node_t* c, ebpf_t* e) {
    if (!strcmp(c->name, "out")) {
		compile_call(c, e);
		return;
	}


	node_t* args = c->call.args;
    node_t* n;
    
    for (n = args; n != NULL; n = n->next) {
        node_walk(n, e);
    }
    
    compile_call(c, e);
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
            get_annot(n, e);
            node_call_walk(n, e);
            break;
        case NODE_INT:
            get_annot(n, e);
            break;
        case NODE_MAP:
            compile_map_load(n ,e);
            break;
        case NODE_STRING:
            get_annot(n, e);
            compile_str(e, n);
            break;
        default:
            break;
    }
}

char* read_file(const char *filename) {
    char *input = (char *) calloc(BUFSIZ, sizeof(char));
    assert(input != NULL);
    uint32_t size = 0;

    FILE *f = fopen(filename, "r");
    if (!f) {
        printf("Could not open \"%s\" for reading", filename);
        exit(1);
    }   

    uint32_t read = 0;
    while ( (read = fread(input, sizeof(char), BUFSIZ, f)) > 0) {
        size += read;

        if (read >= BUFSIZ) {
            input = (char*) realloc(input, size + BUFSIZ);
            assert(input != NULL);
        }   
    }   
    input[size] = '\0';

	fclose(f);
    return input;
}


static int term_sig = 0;
static void term(int sig) {
	term_sig = sig;
	return;
}

int main(int argc, char** argv) {
	char* filename, *input;

    if (argc != 2) {
        return 0;
    }   
    
    filename = argv[1];
	input = read_file(filename);

	if (!input) {
        _errno("readfile error\n");
        return 0;
    }
	
	lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_program(p);
	ebpf_t* e = ebpf_new();
	evpipe_init(e->evp, 4 << 10);		
   
	ebpf_emit(e, MOV(BPF_REG_9, BPF_REG_1));
    node_walk(n, e);
    ebpf_reg_bind(e, &e->st->reg[BPF_REG_0], n);
    ebpf_emit(e, EXIT);
    
    tracepoint_setup(e, n->probe.traceid);   
	evpipe_loop(e->evp, &term_sig, 0);	
    return 0;
}
