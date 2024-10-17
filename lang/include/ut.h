#ifndef UT_H
#define UT_H

#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdnoreturn.h>

#define _size(arr) (sizeof(arr) / sizeof((arr)[0]))
#define _foreach(_n, _in) for ((_n) = (_in); (_n); (_n) = (_n)->next)
#define __printf(a, b)	__attribute__((format(printf, a, b)))

#define _d(_fmt, ...)\
    fprintf(stderr, "DBG %-20s: " _fmt "\n", __func__, ##__VA_ARGS__);

#define _e(_fmt, ...) \
	fprintf(stderr, "ERR %-20s: " _fmt "\n", __func__, ##__VA_ARGS__);


#define __pr(_level, _fmt, ...)\
do{\
    ut_print(_level, "voyant: " _fmt, ##__VA_ARGS__);\
}while(0)

#define _pr_warn(_fmt, ...) __pr(PRINT_WARN, _fmt,  ##__VA_ARGS__)
#define _pr_info(_fmt, ...)  __pr(PRINT_INFO, _fmt,  ##__VA_ARGS__)
#define _pr_debug(_fmt, ...) __pr(PRINT_DEBUG, _fmt,  ##__VA_ARGS__)

static inline void* ERR_PTR(long error_) {
    return (void*) error_;
}

static inline long PTR_ERR(const void* ptr) {
    return (long) ptr;
}

enum print_level {
    PRINT_WARN,
    PRINT_INFO,
    PRINT_DEBUG,
};

typedef int(*ut_print_fn_t)(enum print_level level, const char*, va_list ap);

typedef struct vec_t {
    int len;
    int cap;
    void **data;
} vec_t;

extern noreturn void verror(char *fmt, ...);
extern vec_t *vec_new();
extern void vec_push(vec_t *vec, void *data);
extern bool vec_contains(vec_t *vec, void *elem);
extern bool vec_union(vec_t *vec, void *elem);
extern void *vmalloc(size_t len);
extern void *vcalloc(size_t len1, size_t len2);
extern void *vrealloc(void *p, size_t size);
extern bool vstreq(char *s1, char *s2);
extern char *vstr(char *str);
extern char *str_escape(char *str);
extern FILE *fopenf(const char *mode, const char *fmt, ...);
extern char* read_file(char* name);
extern void output_hist(FILE* fp, int log2, int64_t count, int64_t max);
#endif