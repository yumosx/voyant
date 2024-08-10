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

void compile_call(node_t* n, ebpf_t* e) {
    if(!strcmp(n->name, "pid")) {
        compile_pid(n, e);
    } else if (!strcmp(n->name, "cpu")) {
        compile_cpu(n, e);
    }
}

void node_probe_walk(node_t* p, ebpf_t* e) {
    node_t* n, *stmts;
    p->probe.traceid = get_id(p->probe.name);

    printf("Attaching to probe '%s' with trace id: %d\n", p->probe.name, p->probe.traceid); 
    
    stmts = p->probe.stmts;

    _foreach(n, stmts) {
        compile_walk(n, e);
    }
}

void node_assign_walk(node_t* a, ebpf_t* e) {
    node_t* expr = a->assign.expr;
    compile_sym_assign(a, e);
}

void node_call_walk(node_t* c, ebpf_t* e) {
    node_t* args, *n;

    if (!strcmp(c->name, "out")) {
        node_t* rec = c->call.args->next;
        compile_out(rec, e); 
        return;
	}

    _foreach(n, c->call.args) {
        compile_walk(n, e);
    }

    compile_call(c, e);
}

void compile_walk(node_t* n, ebpf_t* e) {
    switch(n->type) {
        case NODE_PROBE:
            node_probe_walk(n, e);
            break;
        case NODE_ASSIGN:
            compile_sym_assign(n, e);
            break;
        case NODE_CALL:
            node_call_walk(n, e);
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
        _errmsg("readfile error\n");
        return 0;
    }
	
	lexer_t* l = lexer_init(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_program(p);
	ebpf_t* e = ebpf_new();
	
    evpipe_init(e->evp, 4 << 10);		
   
	ebpf_emit(e, MOV(BPF_REG_9, BPF_REG_1));
    
    node_pre_traversal(n, get_annot, loc_assign, e);
    compile_walk(n, e);
    compile_return(n, e);

    tracepoint_setup(e, n->probe.traceid);   
	
    siginterrupt(SIGINT, 1);
    signal(SIGINT, term);
    evpipe_loop(e->evp, &term_sig, 0);	
    return 0;
}