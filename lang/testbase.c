#include <stdio.h>

node_t* parser_test(char* input) {
    lexer_t* l = lexer_int(input);
    parser_t* p = parser_init(l);
    node_t* n = parse_program(p);
    return n;        
}
