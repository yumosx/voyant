#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lang/include/test_framework.h"
#include "../lang/include/lexer.h"

test_suite_t* g_current_suite;

void test_single_char_tokens(test_suite_t* suite);
void test_two_char_tokens(test_suite_t* suite);
void test_keywords(test_suite_t* suite);
void test_identifiers(test_suite_t* suite);
void test_numbers(test_suite_t* suite);
void test_strings(test_suite_t* suite);
void test_comments(test_suite_t* suite);
void test_whitespace(test_suite_t* suite);
void test_illegal_tokens(test_suite_t* suite);
void test_eof(test_suite_t* suite);

TEST_SUITE(lexer_tests) {
    TEST_CASE(single_char_tokens);
    TEST_CASE(two_char_tokens);
    TEST_CASE(keywords);
    TEST_CASE(identifiers);
    TEST_CASE(numbers);
    TEST_CASE(strings);
    TEST_CASE(comments);
    TEST_CASE(whitespace);
    TEST_CASE(illegal_tokens);
    TEST_CASE(eof);
}

void test_single_char_tokens(test_suite_t* suite) {
    lexer_t *lexer = lexer_init(",");
    token_t *token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_COMMA, token->type);
    ASSERT_STR_EQ(",", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("(");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(LEFT_PAREN, token->type);
    ASSERT_STR_EQ("(", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init(")");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(RIGHT_PAREN, token->type);
    ASSERT_STR_EQ(")", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("[");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(LEFT_BRACKET, token->type);
    ASSERT_STR_EQ("[", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("]");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(RIGHT_BRACKET, token->type);
    ASSERT_STR_EQ("]", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("{");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(LEFT_BLOCK, token->type);
    ASSERT_STR_EQ("{", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("}");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(RIGHT_BLOCK, token->type);
    ASSERT_STR_EQ("}", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init(";");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_SEMICOLON, token->type);
    ASSERT_STR_EQ(";", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("+");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_PLUS, token->type);
    ASSERT_STR_EQ("+", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("*");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_STAR, token->type);
    ASSERT_STR_EQ("*", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("#");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_HASH, token->type);
    ASSERT_STR_EQ("#", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("/");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_SLASH, token->type);
    ASSERT_STR_EQ("/", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("-");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_SUB, token->type);
    ASSERT_STR_EQ("-", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("=");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_ASSIGN, token->type);
    ASSERT_STR_EQ("=", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init(":");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_COLON, token->type);
    ASSERT_STR_EQ(":", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);
}

void test_two_char_tokens(test_suite_t* suite) {
    lexer_t *lexer = lexer_init("<=");
    token_t *token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_LE, token->type);
    ASSERT_STR_EQ("<=", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init(">=");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_GE, token->type);
    ASSERT_STR_EQ(">=", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("->");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_ACCESS, token->type);
    ASSERT_STR_EQ("->", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("|>");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_PIPE, token->type);
    ASSERT_STR_EQ("|>", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("==");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_EQ, token->type);
    ASSERT_STR_EQ("==", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init(":=");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_DEC, token->type);
    ASSERT_STR_EQ(":=", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);
}

void test_keywords(test_suite_t* suite) {
    lexer_t *lexer = lexer_init("probe");
    token_t *token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_PROBE, token->type);
    ASSERT_STR_EQ("probe", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("BEGIN");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_BEGIN, token->type);
    ASSERT_STR_EQ("BEGIN", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("END");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_END, token->type);
    ASSERT_STR_EQ("END", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("if");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_IF, token->type);
    ASSERT_STR_EQ("if", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("unroll");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_UNROLL, token->type);
    ASSERT_STR_EQ("unroll", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);
}

void test_identifiers(test_suite_t* suite) {
    lexer_t *lexer = lexer_init("variable");
    token_t *token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_IDENT, token->type);
    ASSERT_STR_EQ("variable", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("my_var123");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_IDENT, token->type);
    ASSERT_STR_EQ("my_var123", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("_underscore");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_IDENT, token->type);
    ASSERT_STR_EQ("_underscore", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);
}

void test_numbers(test_suite_t* suite) {
    lexer_t *lexer = lexer_init("123");
    token_t *token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_INT, token->type);
    ASSERT_STR_EQ("123", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("0");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_INT, token->type);
    ASSERT_STR_EQ("0", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("999999");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_INT, token->type);
    ASSERT_STR_EQ("999999", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);
}

void test_strings(test_suite_t* suite) {
    lexer_t *lexer = lexer_init("\"hello\"");
    token_t *token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_STRING, token->type);
    ASSERT_STR_EQ("hello", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("\"world\"");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_STRING, token->type);
    ASSERT_STR_EQ("world", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("\"\"");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_STRING, token->type);
    ASSERT_STR_EQ("", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);
}

void test_comments(test_suite_t* suite) {
    lexer_t *lexer = lexer_init("// this is a comment\nprobe");
    token_t *token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_PROBE, token->type);
    ASSERT_STR_EQ("probe", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("// comment\n123");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_INT, token->type);
    ASSERT_STR_EQ("123", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);
}

void test_whitespace(test_suite_t* suite) {
    lexer_t *lexer = lexer_init("   probe");
    token_t *token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_PROBE, token->type);
    ASSERT_STR_EQ("probe", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("\t\t123");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_INT, token->type);
    ASSERT_STR_EQ("123", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("\n\nvariable");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_IDENT, token->type);
    ASSERT_STR_EQ("variable", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("\r\r\rhello");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_IDENT, token->type);
    ASSERT_STR_EQ("hello", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);
}

void test_illegal_tokens(test_suite_t* suite) {
    lexer_t *lexer = lexer_init("@");
    token_t *token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_ILLEGAL, token->type);
    ASSERT_NULL(token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("$");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_ILLEGAL, token->type);
    ASSERT_NULL(token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("%");
    token = lexer_next_token(lexer);
    
    ASSERT_EQ(TOKEN_ILLEGAL, token->type);
    ASSERT_NULL(token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);
}

void test_eof(test_suite_t* suite) {
    lexer_t *lexer = lexer_init("");
    token_t *token = lexer_next_token(lexer);
    
    ASSERT_EQ(END_OF_FILE, token->type);
    ASSERT_STR_EQ("", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);

    lexer = lexer_init("probe");
    token = lexer_next_token(lexer);
    token_destroy(token);
    
    token = lexer_next_token(lexer);
    ASSERT_EQ(END_OF_FILE, token->type);
    ASSERT_STR_EQ("", token->literal);
    
    token_destroy(token);
    lexer_destroy(lexer);
}

int main(int argc, char *argv[]) {
    test_suite_t* suite = test_suite_create("Lexer Tests");
    g_current_suite = suite;
    
    test_suite_lexer_tests(suite);
    
    test_suite_print_results(suite);
    
    int exit_code = (suite->failed == 0) ? 0 : 1;
    test_suite_destroy(suite);
    
    return exit_code;
}
