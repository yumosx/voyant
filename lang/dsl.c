#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <linux/bpf.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/version.h>
#include <linux/perf_event.h>

#include "dsl.h"
#include "buffer.h"
#include "annot.h"
#include "ut.h"
#include "bpfsyscall.h"
#include "compiler.h"

int get_id(char *name) {
    char *buffer;
    FILE *fp;
    int number;

    buffer = vmalloc(256);
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

void compile_call(node_t *n, ebpf_t *e) {
    if (!strcmp(n->name, "pid")) {
        compile_pid(n, e);
    }
    else if (!strcmp(n->name, "cpu")) {
        compile_cpu(n, e);
    }
}

void node_probe_walk(node_t *p, ebpf_t *e) {
    node_t *n, *stmts;
    
    stmts = p->probe.stmts;
    _foreach(n, stmts) {
        compile_walk(n, e);
    }
}

void node_assign_walk(node_t *a, ebpf_t *e) {
    node_t *expr = a->assign.expr;
    compile_sym_assign(a, e);
}

void node_call_walk(node_t *c, ebpf_t *e) {
    node_t *args, *n;

    if (vstreq(c->name, "out")) {
        node_t *rec = c->call.args->next;
        compile_out(rec, e);
        return;
    }

    _foreach(n, c->call.args) {
        compile_walk(n, e);
    }

    compile_call(c, e);
}

void compile_walk(node_t *n, ebpf_t *e) {
    switch (n->type) {
    case NODE_PROBE:
        node_probe_walk(n, e);
        break;
    case NODE_DEC:
    case NODE_ASSIGN:
        compile_sym_assign(n, e);
        break;
    case NODE_INFIX_EXPR:
        compile_map_method(n, e);
        break;
    case NODE_CALL:
        node_call_walk(n, e);
        break;
    default:
        break;
    }
}

char *read_file(const char *filename) {
    char *input = (char *)calloc(BUFSIZ, sizeof(char));
    assert(input != NULL);
    uint32_t size = 0;

    FILE *f = fopen(filename, "r");
    if (!f) {
        printf("Could not open \"%s\" for reading", filename);
        exit(1);
    }

    uint32_t read = 0;
    while ((read = fread(input, sizeof(char), BUFSIZ, f)) > 0) {
        size += read;

        if (read >= BUFSIZ) {
            input = (char *)realloc(input, size + BUFSIZ);
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

void compile(node_t* n, ebpf_t* e) {
    evpipe_init(e->evp, 4<<10);
    ebpf_emit(e, MOV(BPF_CTX_REG, BPF_REG_1));
    visit(n, get_annot, loc_assign, e);
    compile_walk(n, e);
    compile_return(n, e); 
}

void run(char* name, ebpf_t* e) {
    int id;

    if (vstreq(name, "BEGIN")) {
        bpf_test_attach(e);
        evpipe_loop(e->evp, &term_sig, 0);
        return;
    }

    siginterrupt(SIGINT, 1);
    signal(SIGINT, term);
    
    id = get_id(name);
    bpf_probe_attach(e, id);
    evpipe_loop(e->evp, &term_sig, -1);
}

int main(int argc, char **argv) {
    char *filename, *input, *name;
    lexer_t* l;
    parser_t* p;
    node_t* head, *n, *map;
    symtable_t* st;
    ebpf_t* e;

    if (argc != 2) {
        return 0;
    }

    filename = argv[1];
    input = read_file(filename);

    if (!input) {
        verror("can not read file");
    }

    l = lexer_init(input);
    p = parser_init(l);
    n = parse_program(p);

    _foreach(head, n) {
        int i;
        e = ebpf_new();
        st = e->st;

        name = head->probe.name;
        compile(head, e);
        run(name, e);   

        for (i = 0; i < st->len; i++) {
            if (st->table[i].type == SYM_MAP) {
                map_dump(st->table[i].map->map);
            }
        }
    }

    return 0;
}
