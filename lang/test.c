#include "parser.h"
#include "lexer.h"
#include "ast.h"
#include "ut.h"

void test_parse_block() {

}

int main(int argc, char** argv) {
    char* string, *filename;
    lexer_t* lexer;
    parser_t* parser;
    node_t* node;

    if (argc != 2) {
        return 0;
    }

    filename = argv[1];
    string = read_file(filename);
    
    if (!string) {
        verror("read file error");
    }
    

    lexer =  lexer_init(string);
    parser = parser_init(lexer);

    return 0;
}