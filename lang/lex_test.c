#include <string.h>

#include "testbase.h"

static void test_lexer() {
    char* input = "probe sys_enter_execve /a == 1/ {a = 1; printf(); a[];}";
   
    token_t toks [] = {
        {"probe", TOKEN_PROBE},
        {"sys_enter_execve", TOKEN_IDENT},
        {"/", TOKEN_SLASH},
        {"a", TOKEN_IDENT},
        {"==", TOKEN_EQ},
        {"1", TOKEN_INT},
        {"/", TOKEN_SLASH},
        {"{", TOKEN_LEFT_BLOCK},
        {"a", TOKEN_IDENT},
        {"=", TOKEN_ASSIGN},
        {"1", TOKEN_INT},
        {";", TOKEN_SEMICOLON},
        {"printf", TOKEN_IDENT},
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
        free_token(t);
    }

    free_lexer(lexer);
}

int main() {
    test_lexer();
    PRINT_ANS();
    return 0;
}
