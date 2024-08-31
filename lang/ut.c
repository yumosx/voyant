#include <stdio.h>

#include "ut.h"

noreturn void verror(char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	exit(1);
}

FILE* fopenf(const char* mode, const char* fmt, ...) {
	va_list ap;
	FILE* fp;
	char* path;
	va_start(ap, fmt);
	vasprintf(&path, fmt, ap);
	va_end(ap);

	fp = fopen(path, mode);
	free(path);
	return fp;
}	

void* vmalloc(size_t len) {
	void* obj = malloc(len);
	if (!obj) {
		fprintf(stderr, "\n malloc failed\n");
		exit(1);
	}
	return obj;
}

void* vrealloc(void* p, size_t size) {
	void* obj = realloc(p, size);
	if (!obj) {
		fprintf(stderr, "\n Rand out of memory (realloc)\n");
		exit(1);
	}
	return obj;
}


void* vcalloc(size_t num, size_t size) {
	void* obj = calloc(num, size);
	if (!obj) {
		fprintf(stderr, "\n Rand out of memory (calloc)\n");
		exit(1);
	}
	return obj;
}

char* vstr(char* s) {
	char* p = vmalloc(strlen(s) + 1);
	strcpy(p, s);
	return p;
}

bool vstreq(char* s1, char* s2) {
	return strcmp(s1, s2) == 0;
}

char* str_escape(char* str) {
	char* in, *out;

	for (in = out = str; *in; in++, out++) {
		if (*in != '\\')
			continue;
		in++;
		switch (*in) {
		case 'n':
			*out = '\n';
			break;
		case 't':
			*out = '\t';
			break;
		case '\\':
			*out = '\\';
			break;
		default:
			break;
		}
	}
	if (out < in)
		*out = '\0';
	return str;
}
