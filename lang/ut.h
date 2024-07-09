#ifndef UT_H
#define UT_H

typedef struct vector vector_t;

struct vector{
	void** data;
	int len;
	int cap;
};

extern void* checked_malloc(size_t len);
extern void* checked_calloc(size_t len1, size_t len2);
extern void* checked_realloc(void* p, size_t size);
extern char* ut_str(char* str);
extern vector_t* vec_new();
extern void vec_push(vector_t* v, void* elem);

#endif
