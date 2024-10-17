#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
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

void vec_free(vec_t* vec) {
	int i;
	
	for (i = 0; i < vec->len; i++) {
		free(vec->data[i]);
	}

	free(vec->data);
	free(vec);
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

static int base_pr(enum print_level level, const char* format, va_list args) {
	const char* env_var = "VY_LOG_LEVEL";
	static enum print_level min_level = PRINT_INFO;
	static bool initialized;

	if (!initialized) {
		char* verbosity;

		initialized = true;
		verbosity = getenv(env_var);
		if (verbosity) {
			if (strcasecmp(verbosity, "warn") == 0) {
				min_level = PRINT_WARN;
			} else if (strcasecmp(verbosity, "debug") == 0) {
				min_level = PRINT_DEBUG;
			} else if (strcasecmp(verbosity, "info") == 0) {
				min_level = PRINT_INFO;
			} else {
				fprintf(stderr, "voyant: unrecognized '%s' envvar value: '%s', should be one of 'warn', 'debug', or 'info'.\n",
					env_var, verbosity);
			}
		}
	}

	if (level > min_level) {
		return 0;
	}

	return vfprintf(stderr, format, args);
}

static ut_print_fn_t __vy_pr = base_pr;

__printf(2, 3)
void ut_print(enum print_level level, const char* format, ...) {
	va_list args;
	int old_errno;
	ut_print_fn_t print_fn;

	print_fn = __atomic_load_n(&__vy_pr, __ATOMIC_RELAXED);
	if (!print_fn)
		return;
	
	old_errno = errno;
	va_start(args, format);
	__vy_pr(level, format, args);
	va_end(args);

	errno = old_errno;
}

char* ut_strerror_r(int err, char* dst, int len) {
	int ret = strerror_r(err < 0 ? -err : err, dst, len);
	if (ret == -1)
		ret = errno;
	
	if (ret) {
		if (ret == EINVAL)
			snprintf(dst, len, "unknown error (%d)", err < 0 ? err : -err);
		else
			snprintf(dst, len, "ERROR: strerror_r(%d)=%d", err, ret);
		}

	return dst;
}