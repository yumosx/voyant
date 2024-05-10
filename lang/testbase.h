#ifndef TEST_BASE
#define TEST_BASE

#include <stdio.h>
#include "lexer.h"

static int main_ret = 0;
static int test_count = 0;
static int test_pass = 0;

#define EXPECT_EQ_BASE(_eq, _expect, _actual, _format) \
    do{\
        test_count++; \
        if (_eq) { \
            test_pass++;\
        } else { \
            fprintf(stderr, "%s:%d: expect: " _format " actual: " _format "\n", __FILE__, __LINE__, _expect, _actual);\
            main_ret++;\
        }\
    }while(0)\

#define EXPECT_EQ_STR(_expect, _actual) EXPECT_EQ_BASE(strcmp((_expect), (_actual)) == 0, _expect, _actual, "%s")
#define EXPECT_EQ_INT(_expect, _actual) EXPECT_EQ_BASE((_expect) == (_actual), _expect, _actual, "%ld")
#define PRINT_ANS() printf("%d/%d (%3.2f%%) passed\n", test_pass, test_count, test_pass * 100.0 / test_count);

#endif
