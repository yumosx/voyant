#ifndef UT_H
#define UT_H

#define _size(arr) (sizeof(arr) / sizeof(arr[0]))

#define _error(_fmt, ...) \
	fprintf(stderr, "ERR %-20s: " _fmt "\n", __func__, ##__VA_ARGS__)

#define _errmsg(_fmt, ...) \
	fprintf(stderr, "ERR %-20s: " _fmt " : %m\n", __func__, ##__VA_ARGS__)

#define _foreach(_n, _in) for ((_n)=(_in); (_n); (_n) = (_n)->next)

extern void* checked_malloc(size_t len);
extern void* checked_calloc(size_t len1, size_t len2);
extern void* checked_realloc(void* p, size_t size);
extern char* ut_str(char* str);

#endif
