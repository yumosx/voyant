#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

#include "ut.h"

noreturn void verror(char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	exit(1);
}

vec_t *vec_new() {
	vec_t *vec = vmalloc(sizeof(vec));
	vec->data = vmalloc(sizeof(void *) * 16);
	vec->cap = 16;
	vec->len = 0;
	return vec;
}

void vec_push(vec_t *vec, void *elem) {
	if (vec->len == vec->cap) {
		vec->cap *= 2;
		vec->data = realloc(vec->data, sizeof(void *) * vec->cap);
	}
	vec->data[vec->len++] = elem;
}

bool vec_contains(vec_t *vec, void *elem) {
	int i;

	for (i = 0; i < vec->len; i++) {
		if (vec->data[i] == elem) {
			return true;
		}
	}
	return false;
}

bool vec_union(vec_t *vec, void *elem) {
	if (vec_contains(vec, elem)) {
		return false;
	}

	vec_push(vec, elem);
	return true;
}

FILE *fopenf(const char *mode, const char *fmt, ...) {
	va_list ap;
	FILE *fp;
	char *path;
	va_start(ap, fmt);
	vasprintf(&path, fmt, ap);
	va_end(ap);

	fp = fopen(path, mode);
	free(path);
	return fp;
}

void *vmalloc(size_t len) {
	void *obj = malloc(len);
	if (!obj) {
		fprintf(stderr, "\n malloc failed\n");
		exit(1);
	}
	return obj;
}

void *vrealloc(void *ptr, size_t size) {
	void *obj = realloc(ptr, size);
	
	if (!obj) {
		fprintf(stderr, "\n Rand out of memory (realloc)\n");
		exit(1);
	}
	return obj;
}

void *vcalloc(size_t num, size_t size) {
	void *obj = calloc(num, size);
	if (!obj) {
		fprintf(stderr, "\n Rand out of memory (calloc)\n");
		exit(1);
	}
	return obj;
}

char *vstr(char *str) {
	char *p = vmalloc(strlen(str) + 1);
	strcpy(p, str);
	return p;
}

bool vstreq(char *s1, char *s2) {
	return strcmp(s1, s2) == 0;
}

char *str_escape(char *str) {
	char *in, *out;

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

void print_line(char *buf, char *path, char *pos) {
	char *start, *p;
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

		fprintf(stderr, "error at %s:%d:%d\n\n", path, line + 1, col + 1);
		linelen = strchr(p, '\n') - start;
		fprintf(stderr, "%.*s\n", linelen, start);

		for (i = 0; i < col; i++) {
			fprintf(stderr, (start[i] == '\t') ? "\t" : " ");
		}
		fprintf(stderr, "^\n\n");
		return;
	}
}

char *read_file(char *filename) {
	char *input = (char *)calloc(BUFSIZ, sizeof(char));
	assert(input != NULL);
	uint32_t size = 0, read;

	FILE *f = fopen(filename, "r");

	if (!f) {
		verror("Could not open \"%s\" for reading", filename);
		exit(1);
	}

	while ((read = fread(input, sizeof(char), BUFSIZ, f)) > 0) {
		size += read;

		if (read >= BUFSIZ) {
			input = vrealloc(input, size + BUFSIZ);
			assert(input != NULL);
		}
	}
	input[size] = '\0';

	fclose(f);
	return input;
}