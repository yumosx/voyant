#ifndef UT_H
#define UT_H

#include <stdarg.h>
#include <stdnoreturn.h>

#define _size(arr) (sizeof(arr) / sizeof(arr[0]))

#define _error(_fmt, ...) \
	fprintf(stderr, "ERR %-20s: " _fmt "\n", __func__, ##__VA_ARGS__)

#define _errmsg(_fmt, ...) \
	fprintf(stderr, "ERR %-20s: " _fmt " : %m\n", __func__, ##__VA_ARGS__)

#define _foreach(_n, _in) for ((_n)=(_in); (_n); (_n) = (_n)->next)

extern noreturn void verror(char* fmt, ...);
extern void* vmalloc(size_t len);
extern void* vcalloc(size_t len1, size_t len2);
extern void* vrealloc(void* p, size_t size);
extern char* vstr(char* str);
extern char* str_escape(char* str);
#endif
