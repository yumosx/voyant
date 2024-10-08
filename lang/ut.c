#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <inttypes.h>

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


void print_bar_ascii(FILE *fp, int64_t count, int64_t max) {
	int w = (((float)count / (float)max) * 32.0) + 0.5;
	int i;

	fputc('|', fp);

	for (i = 0; i < 32; i++, w--)
		fputc((w > 0) ? '@' : ' ', fp);

	fputc('|', fp);
}

static int quantize_normalize(int log2, char* const** suffix) {
    static const char* s[] = {NULL, "k", "M", "G", "T", "P", "Z"};
    int i;

    for (i = 0; log2 >= 10; i++, log2 -= 10);
    *suffix = s[i];

    return (1 << log2);
}

void output_hist(FILE* fp, int log2, int64_t count, int64_t max) {
    int lo, hi;
    const char* ls, *hs;
    
    switch (log2) {
    case -1:
        fputs("\t         < 0", fp);
        break;
    case 0:
        fputs("\t           0", fp);
        break;
    case 1:
        fputs("\t           1", fp);
        break;
    default:
        lo = quantize_normalize(log2-1, &ls);
        hi = quantize_normalize(log2, &hs);

        if (!hs)
			fprintf(fp, "\t[%4d, %4d]", lo, hi - 1);
		else
			fprintf(fp, "\t[%*d%s, %*d%s)",
				ls ? 3 : 4, lo, ls ? : "",
				hs ? 3 : 4, hi, hs ? : "");
    }
	
	fprintf(fp, "\t%8" PRId64 " ", count);
	print_bar_ascii(fp, count, max);
    fputc('\n', fp);
}