#ifndef UT_H
#define UT_H

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <stdnoreturn.h>

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)
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


static inline bool IS_ERR_OR_NULL(const void* ptr) {
    return (!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

static inline void* ERR_PTR(long error_) {
    return (void*) error_;
}

static inline long PTR_ERR(const void* ptr) {
    return (long) ptr;
}

static inline long IS_ERR(const void* ptr) {
    return IS_ERR_VALUE((unsigned long) ptr);
}

static inline void* ut_err(void* ret) {
    if (IS_ERR(ret)) {
        errno = -PTR_ERR(ret);
    }

    return IS_ERR(ret) ? NULL : ret;
}

static inline void* ut_ptr(void* ret) {
    if (IS_ERR(ret))
        errno = -PTR_ERR(ret);
    
    return IS_ERR(ret) ? NULL : ret;
}

static inline int libbpf_err(int ret) {
    if (ret < 0)
        errno = -ret;
    
    return ret;
}

static inline void *ut_reallocarray(void *ptr, size_t nmemb, size_t size) {
	size_t total;

	total = nmemb * size;
	return realloc(ptr, total);
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
extern long get_error(const void* ptr);
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
extern void *ut_add_mem(void **data, size_t *cap_cnt, size_t elem_sz,
		     size_t cur_cnt, size_t max_cnt, size_t add_cnt);
#endif