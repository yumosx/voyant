#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_MAX_NAME_LEN 256
#define TEST_MAX_MSG_LEN 1024

typedef struct test_result {
  char name[TEST_MAX_NAME_LEN];
  bool passed;
  char message[TEST_MAX_MSG_LEN];
  const char *file;
  int line;
} test_result_t;

typedef struct test_suite {
  char name[TEST_MAX_NAME_LEN];
  test_result_t *results;
  int result_count;
  int result_capacity;
  int passed;
  int failed;
} test_suite_t;

typedef void (*test_func_t)(test_suite_t *suite);

extern test_suite_t *g_current_suite;

#define TEST_SUITE(name) void test_suite_##name(test_suite_t *suite)

#define TEST_CASE(test_name)                                                   \
  do {                                                                         \
    test_result_t *result =                                                    \
        &g_current_suite->results[g_current_suite->result_count];              \
    memset(result, 0, sizeof(test_result_t));                                  \
    do {                                                                       \
      const char *__test_name_str = #test_name;                                \
      strncpy(result->name, __test_name_str, TEST_MAX_NAME_LEN - 1);           \
    } while (0);                                                               \
    result->file = __FILE__;                                                   \
    result->line = __LINE__;                                                   \
    result->passed = true;                                                     \
    g_current_suite->result_count++;                                           \
    test_##test_name(g_current_suite);                                         \
  } while (0)

#define ASSERT_EQ(expected, actual)                                            \
  do {                                                                         \
    if ((expected) != (actual)) {                                              \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN,                                 \
               "Assertion failed: %s == %s (%lld != %lld)", #expected,         \
               #actual, (long long)(expected), (long long)(actual));           \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_NE(expected, actual)                                            \
  do {                                                                         \
    if ((expected) == (actual)) {                                              \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN,                                 \
               "Assertion failed: %s != %s (both are %lld)", #expected,        \
               #actual, (long long)(expected));                                \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_TRUE(condition)                                                 \
  do {                                                                         \
    if (!(condition)) {                                                        \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN,                                 \
               "Assertion failed: %s is false", #condition);                   \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_FALSE(condition)                                                \
  do {                                                                         \
    if (condition) {                                                           \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN, "Assertion failed: %s is true", \
               #condition);                                                    \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_NULL(ptr)                                                       \
  do {                                                                         \
    if ((ptr) != NULL) {                                                       \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN,                                 \
               "Assertion failed: %s is not NULL", #ptr);                      \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_NOT_NULL(ptr)                                                   \
  do {                                                                         \
    if ((ptr) == NULL) {                                                       \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN, "Assertion failed: %s is NULL", \
               #ptr);                                                          \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_STR_EQ(expected, actual)                                        \
  do {                                                                         \
    if (strcmp((expected), (actual)) != 0) {                                   \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN,                                 \
               "Assertion failed: strings \"%s\" != \"%s\"", (expected),       \
               (actual));                                                      \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_STR_NE(expected, actual)                                        \
  do {                                                                         \
    if (strcmp((expected), (actual)) == 0) {                                   \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN,                                 \
               "Assertion failed: strings are equal: \"%s\"", (expected));     \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_LT(a, b)                                                        \
  do {                                                                         \
    if ((a) >= (b)) {                                                          \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN,                                 \
               "Assertion failed: %s < %s (%lld >= %lld)", #a, #b,             \
               (long long)(a), (long long)(b));                                \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_LE(a, b)                                                        \
  do {                                                                         \
    if ((a) > (b)) {                                                           \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN,                                 \
               "Assertion failed: %s <= %s (%lld > %lld)", #a, #b,             \
               (long long)(a), (long long)(b));                                \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_GT(a, b)                                                        \
  do {                                                                         \
    if ((a) <= (b)) {                                                          \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN,                                 \
               "Assertion failed: %s > %s (%lld <= %lld)", #a, #b,             \
               (long long)(a), (long long)(b));                                \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_GE(a, b)                                                        \
  do {                                                                         \
    if ((a) < (b)) {                                                           \
      test_result_t *res =                                                     \
          &g_current_suite->results[g_current_suite->result_count - 1];        \
      res->passed = false;                                                     \
      snprintf(res->message, TEST_MAX_MSG_LEN,                                 \
               "Assertion failed: %s >= %s (%lld < %lld)", #a, #b,             \
               (long long)(a), (long long)(b));                                \
      res->file = __FILE__;                                                    \
      res->line = __LINE__;                                                    \
      return;                                                                  \
    }                                                                          \
  } while (0)

test_suite_t *test_suite_create(const char *name);
void test_suite_destroy(test_suite_t *suite);
void test_suite_run(test_suite_t *suite);
void test_suite_print_results(test_suite_t *suite);

#endif
