#include "parser.h"
#include "lexer.h"
#include "ast.h"
#include "ut.h"

#include "test.h"

lexer_t* lexer;
parser_t* parser;
node_t* node;

tstsuite("test the parser") {
    tstcase("test the expr parser") {
        char* string = "{ a := 1 + 2 * 3;}";
        lexer = lexer_init(string);
        parser = parser_init(lexer);
        node = parse_block_stmts(parser);
    
        tstcheck(node->type == NODE_DEC);
        tstcheck(node->dec.expr->expr.left->type == NODE_INT);
        tstcheck(node->dec.expr->expr.opcode == OP_ADD);
        tstcheck(node->dec.expr->expr.right->type == NODE_EXPR);
        tstcheck(node->dec.expr->expr.right->expr.left->type == NODE_INT);
        tstcheck(node->dec.expr->type == NODE_EXPR);

        free(node);
        free_lexer(lexer);
    }
    
    tstcase("test the block parse") {
        char* string = "{ a := 1; a := 2;}";
        lexer = lexer_init(string);
        parser = parser_init(lexer);
        node = parse_block_stmts(parser);

        tstcheck(parser->this_tok->type == RIGHT_BLOCK);
        tstcheck(node->type == NODE_DEC, "mismatch1");
        tstcheck(node->next->type == NODE_DEC, "mismatch2");
   
        free_lexer(lexer);
        free(node);
   }

   tstcase("sad path") {
        char* string = "{ a := ;}";
        lexer = lexer_init(string);
        parser = parser_init(lexer);
        node = parse_block_stmts(parser);
   }
}