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

void print_map(symtable_t* st) {
    int i;
    for (i = 0; i < st->len; i++) {
        if (st->table[i].type == SYM_MAP) {
            map_dump(st->table[i].map->map);
        }
    }
}

void _free(node_t* node) {
    node_t* head;
    vec_t* vec = vec_new();
    size_t i;

    _foreach(head, node) {
        vec_push(vec, head);
    }

    for (i = 0; i < vec->len; i++) {
        node_t* value = vec->data[i];
        free_node(value);   
    }
    free(vec->data);
    free(vec);
}

void run(node_t* node) {
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
    print_map(st);
}

int main(int argc, char **argv) {
    char* filename, *input;
    lexer_t* lexer;
    parser_t* parser;
    node_t* node;
    ebpf_t* code;
    prog_t* prog;
    int id;
    symtable_t* st;

    if (argc != 2) {
        verror("should have the two args");
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
   
    run(node);
    _free(node);
    return 0;
}