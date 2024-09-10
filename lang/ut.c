#include <stdio.h>
#include <string.h>

#include "ut.h"

noreturn void verror(char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	exit(1);
}

vec_t* vec_new() {
    vec_t* vec = vmalloc(sizeof(vec));
    vec->data = vmalloc(sizeof(void*) * 16);
    vec->cap = 16;
    vec->len = 0;
    return vec;
}

void vec_push(vec_t* v, void* elem) {
    if (v->len == v->cap) {
        v->cap *= 2;
        v->data = realloc(v->data, sizeof(void*)*v->cap);
    }
    v->data[v->len++] = elem;
}

bool vec_contains(vec_t* v, void* elem) {
	int i;

	for (i = 0; i < v->len; i++) {
		if (v->data[i] == elem) {
			return true;
		}
	}
	return false;
}

bool vec_union(vec_t* v, void* elem) {
	if (vec_contains(v, elem)) {
		return false;
	}
	vec_push(v, elem);
	
	return true;
}

FILE* fopenf(const char* mode, const char* fmt, ...) {
	va_list ap;
	FILE* fp;
	char* path;
	va_start(ap, fmt);
	vasprintf(&path, fmt, ap);
	va_end(ap);

	printf("%s\n", path);

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
		case 'r':
			*out = '\r';
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


static void print_line(char* buf, char* path, char* pos) {
	char* start, *p;
	int line = 0;
	int col = 0;
	int linelen = 0;
	int i = 0;


	start = buf;

	for (p = buf; p; p++) {
		if (*p == '\n') {
			start = p + 1;
			line++;
			col = 0;
			continue;
		}

		if (p != pos) {
			col++;
			continue;
		}

		fprintf(stderr, "error at %s:%d:%d\n\n", path, line+1, col+1);
		linelen = strchr(p, '\n') - start;
		fprintf(stderr, "%.*s\n", linelen, start);

		for (i = 0; i < col; i++) {
			fprintf(stderr, (start[i] == '\t') ? "\t" : " ");
		}
		fprintf(stderr, "^\n\n");
		return;
	}	
}