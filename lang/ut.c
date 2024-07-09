#include <stdio.h>
#include "ut.h"

void* checked_malloc(size_t len) {
	void* obj = malloc(len);
	if (!obj) {
		fprintf(stderr, "\n malloc failed\n");
		exit(1);
	}
	return obj;
}

void* checked_realloc(void* p, size_t size) {
	void* obj = realloc(p, size);
	if (!obj) {
		fprintf(stderr, "\n Rand out of memory (realloc)\n");
		exit(1);
	}
	return obj;
}

void* checked_calloc(size_t num, size_t size) {
	void* obj = calloc(num, size);
	if (!obj) {
		fprintf(stderr, "\n Rand out of memory (calloc)\n");
		exit(1);
	}
	return obj;
}


char* ut_str(char* s) {
	char* p = checked_malloc(strlen(s) + 1);
	strcpy(p, s);
	return p;
}


vector_t* vec_new() {
	vector_t* v = checked_malloc(sizeof(*v));
	v->data = checked_malloc(sizeof(void*) * 16);
	v->cap = 16;
	v->len = 0;
	return v;
}


void vec_push(vector_t* v, void* elem) {
	if (v->len == v->cap) {
		v->cap *= 2;
		v->data = checked_realloc(v->data, sizeof(void*) * v->cap);
	}
	v->data[v->len++] = elem;
}
