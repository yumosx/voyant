#include <signal.h>

#include "dsl.h"
#include "ut.h"

static int term_sig = 0;
static void term(int sig) {
    term_sig = sig;
    return;
}

void attach(node_t* node, ebpf_t* ctx, int id) {
    switch (node->type) {
    case NODE_TEST:
        bpf_test_attach(ctx);
        break;
    case NODE_KPROBE:
        bpf_kprobe_attach(ctx, id);
        break;
    case NODE_PROBE:
        bpf_probe_attach(ctx, id);
        break;
    default:
        break;
    }
}

void run_probe(node_t* node) {
    node_t* head;
    ebpf_t* code;
    prog_t* prog;
    symtable_t* st = symtable_new();
    evpipe_t* evp = vcalloc(1, sizeof(*evp));
    evpipe_init(evp, 4<<10);

    _foreach(head, node) {
        code = ebpf_new();
        code->evp = evp;
        code->st = st;

        sema(head, code);
        prog = gen_prog(head);
        prog->ctx = code;
        compile(prog);

        attach(head, prog->ctx, head->probe.traceid);
    }
    
    siginterrupt(SIGINT, 1);
    signal(SIGINT, term);
    evpipe_loop(evp, &term_sig, -1);
}

int main(int argc, char **argv) {
    char* filename, *input;
    lexer_t* lexer;
    parser_t* parser;
    node_t* node, *head;
    ebpf_t* code;
    prog_t* prog;
    int id;
    symtable_t* st;

    if (argc != 2) {
        return 0;
    }

    filename = argv[1];
    input = read_file(filename);

    if (!input) {
        verror("can not read file");
    }

    lexer = lexer_init(input);
    parser = parser_init(lexer);
    node = parse_program(parser);
   
    //run_progs(node);
    run_probe(node);
    return 0;
}