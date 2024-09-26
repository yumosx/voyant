#include <signal.h>

#include "dsl.h"
#include "ut.h"

static int term_sig = 0;
static void term(int sig) {
    term_sig = sig;
    return;
}

int run_progs(node_t* node) {
    node_t* head;
    ebpf_t* code;
    prog_t* prog;
    symtable_t* st;
    int id;
    
    _foreach(head, node) {
        code = ebpf_new();
        evpipe_init(code->evp, 4<<10);
        sema(head, code);
        prog = gen_prog(head);
        prog->ctx = code;
        compile(prog);

        if (vstreq("BEGIN", head->probe.name)) {
            bpf_test_attach(code);
            evpipe_loop(code->evp, &term_sig, 0);
        } else {
            id = bpf_get_probe_id(head->probe.name);
            bpf_probe_attach(prog->ctx, id);
            siginterrupt(SIGINT, 1);
            signal(SIGINT, term);
            evpipe_loop(code->evp, &term_sig, -1);

            st = code->st;
        
            int i;
            for (i = 0; i < st->len; i++) {
                if (st->table[i].type == SYM_MAP) {
                    map_dump(st->table[i].map->map);
                }      
            }
        }
    }
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
   
    run_progs(node);
    return 0;
}