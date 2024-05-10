#include <string.h>

#include "testbase.h"

static void test_lexer() {
    char* input = "probe sys:execute{let a = 1; print(); a[];}";
   
    token_t toks [] = {
        {"probe", TOKEN_PROBE},
        {"sys", TOKEN_IDENT},
        {":", TOKEN_COLON},
        {"execute", TOKEN_IDENT},
        {"{", TOKEN_LEFT_BLOCK},
        {"let", TOKEN_LET},
        {"a", TOKEN_IDENT},
        {"=", TOKEN_ASSIGN},
        {"1", TOKEN_INT},
        {";", TOKEN_SEMICOLON},
        {"print", TOKEN_IDENT},
        {"(", LEFT_PAREN},
        {")", RIGHT_PAREN},
        {";", TOKEN_SEMICOLON},
        {"a", TOKEN_IDENT},
        {"[", TOKEN_LEFT_BRACKET},
        {"]", TOKEN_RIGHT_BRACKET},
        {";", TOKEN_SEMICOLON},
        {"}", TOKEN_RIGHT_BLOCK},
    };

    lexer_t* lexer = lexer_init(input);
    token_t* t;

    for (int i = 0; i < sizeof toks / sizeof toks[0]; i++) {
        t = lexer_next_token(lexer);
        EXPECT_EQ_STR(toks[i].literal, t->literal);
    }
}

/*
int main() {
    test_lexer();
    PRINT_ANS();
    return 0;
}
*/
