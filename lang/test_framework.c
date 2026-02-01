#include "test_framework.h"
#include <stdarg.h>

test_suite_t* g_current_suite = NULL;

test_suite_t* test_suite_create(const char* name) {
    test_suite_t* suite = (test_suite_t*)malloc(sizeof(test_suite_t));
    if (!suite) {
        fprintf(stderr, "Failed to allocate memory for test suite\n");
        return NULL;
    }

    strncpy(suite->name, name, TEST_MAX_NAME_LEN - 1);
    suite->name[TEST_MAX_NAME_LEN - 1] = '\0';
    
    suite->result_capacity = 16;
    suite->results = (test_result_t*)malloc(sizeof(test_result_t) * suite->result_capacity);
    if (!suite->results) {
        fprintf(stderr, "Failed to allocate memory for test results\n");
        free(suite);
        return NULL;
    }
    
    suite->result_count = 0;
    suite->passed = 0;
    suite->failed = 0;
    
    return suite;
}

void test_suite_destroy(test_suite_t* suite) {
    if (suite) {
        free(suite->results);
        free(suite);
    }
}

void test_suite_run(test_suite_t* suite) {
    if (!suite) {
        fprintf(stderr, "Invalid test suite\n");
        return;
    }

    g_current_suite = suite;
    
    printf("\n");
    printf("========================================\n");
    printf("Running Test Suite: %s\n", suite->name);
    printf("========================================\n");
}

void test_suite_print_results(test_suite_t* suite) {
    if (!suite) {
        fprintf(stderr, "Invalid test suite\n");
        return;
    }

    int i;
    
    for (i = 0; i < suite->result_count; i++) {
        test_result_t* result = &suite->results[i];
        
        if (result->passed) {
            suite->passed++;
            printf("[PASS] %s\n", result->name);
        } else {
            suite->failed++;
            printf("[FAIL] %s\n", result->name);
            printf("       %s:%d: %s\n", result->file, result->line, result->message);
        }
    }
    
    printf("\n");
    printf("========================================\n");
    printf("Test Suite: %s\n", suite->name);
    printf("Total: %d, Passed: %d, Failed: %d\n", 
           suite->result_count, suite->passed, suite->failed);
    printf("========================================\n");
    printf("\n");
}

void test_finalize_results(test_suite_t* suite) {
    if (!suite) {
        return;
    }
    
    int i;
    for (i = 0; i < suite->result_count; i++) {
        test_result_t* result = &suite->results[i];
        
        if (result->passed) {
            suite->passed++;
        } else {
            suite->failed++;
        }
    }
}
