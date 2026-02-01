#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ut.h"

noreturn void verror(char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  exit(1);
}

long get_error(const void *ptr) {
  if (!IS_ERR_OR_NULL(ptr)) {
    return 0;
  }

  if (IS_ERR(ptr)) {
    errno = -PTR_ERR(ptr);
  }

  return -errno;
}

#define VEC_INITIAL_CAPACITY 16

vec_t *vec_new() {
  vec_t *vec = vmalloc(sizeof(vec_t));
  vec->data = vmalloc(sizeof(void *) * VEC_INITIAL_CAPACITY);
  vec->cap = VEC_INITIAL_CAPACITY;
  vec->len = 0;
  return vec;
}

void vec_push(vec_t *vec, void *elem) {
  if (vec->len == vec->cap) {
    vec->cap *= 2;
    void *new_data = realloc(vec->data, sizeof(void *) * vec->cap);
    if (!new_data) {
      verror("vec_push: failed to expand vector to capacity %d", vec->cap);
    }
    vec->data = new_data;
  }
  vec->data[vec->len++] = elem;
}

void vec_free(vec_t *vec) {
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
  FILE *file;
  char *path;
  va_start(ap, fmt);
  vasprintf(&path, fmt, ap);
  va_end(ap);
  file = fopen(path, mode);
  free(path);
  return file;
}

void *vmalloc(size_t size) {
  void *ptr = malloc(size);
  if (!ptr) {
    verror("malloc failed: requested %zu bytes", size);
  }
  return ptr;
}

void *vrealloc(void *ptr, size_t size) {
  void *new_ptr = realloc(ptr, size);

  if (!new_ptr && size > 0) {
    verror("realloc failed: requested %zu bytes", size);
  }
  return new_ptr;
}

void *vcalloc(size_t num, size_t size) {
  void *ptr = calloc(num, size);
  if (!ptr) {
    verror("calloc failed: requested %zu elements of %zu bytes", num, size);
  }
  return ptr;
}

char *vstr(char *str) {
  size_t len = strlen(str);
  char *copy = vmalloc(len + 1);
  strncpy(copy, str, len + 1);
  return copy;
}

bool vstreq(char *s1, char *s2) { return strcmp(s1, s2) == 0; }

char *str_escape(char *str) {
  size_t len = strlen(str);
  char *escaped = vmalloc(len + 1);
  char *src = str;
  char *dst = escaped;

  while (*src) {
    if (*src != '\\') {
      *dst++ = *src++;
      continue;
    }
    src++;
    switch (*src) {
    case 'n':
      *dst++ = '\n';
      break;
    case 'r':
      *dst++ = '\r';
      break;
    case 't':
      *dst++ = '\t';
      break;
    case '\\':
      *dst++ = '\\';
      break;
    default:
      *dst++ = *src;
      break;
    }
    src++;
  }
  *dst = '\0';
  return escaped;
}

char *read_file(char *filename) {
  FILE *file = fopen(filename, "r");

  if (!file) {
    verror("Could not open \"%s\" for reading", filename);
  }

  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  char *content = vmalloc(file_size + 1);
  size_t bytes_read = fread(content, 1, file_size, file);

  if (bytes_read != (size_t)file_size) {
    verror("Failed to read complete file \"%s\"", filename);
  }

  content[bytes_read] = '\0';
  fclose(file);

  return content;
}

#define BAR_WIDTH 32

void print_bar_ascii(FILE *fp, int64_t count, int64_t max) {
  int bar_length = (((float)count / (float)max) * BAR_WIDTH) + 0.5;
  int i;

  fputc('|', fp);

  for (i = 0; i < BAR_WIDTH; i++, bar_length--)
    fputc((bar_length > 0) ? '@' : ' ', fp);

  fputc('|', fp);
}

static int quantize_normalize(int log2, const char **suffix) {
  static const char *suffixes[] = {NULL, "k", "M", "G", "T", "P", "Z"};
  int i;

  for (i = 0; log2 >= 10; i++, log2 -= 10)
    ;
  *suffix = suffixes[i];

  return (1 << log2);
}

void output_hist(FILE *fp, int log2, int64_t count, int64_t max) {
  int lower_bound, upper_bound;
  const char *lower_suffix, *upper_suffix;

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
    lower_bound = quantize_normalize(log2 - 1, &lower_suffix);
    upper_bound = quantize_normalize(log2, &upper_suffix);

    if (!upper_suffix)
      fprintf(fp, "\t[%4d, %4d]", lower_bound, upper_bound - 1);
    else
      fprintf(fp, "\t[%*d%s, %*d%s)", lower_suffix ? 3 : 4, lower_bound,
              lower_suffix ?: "", upper_suffix ? 3 : 4, upper_bound,
              upper_suffix ?: "");
  }

  fprintf(fp, "\t%8" PRId64 " ", count);
  print_bar_ascii(fp, count, max);
  fputc('\n', fp);
}

static int base_pr(enum print_level level, const char *format, va_list args) {
  const char *env_var = "VY_LOG_LEVEL";
  static enum print_level min_level = PRINT_INFO;
  static bool initialized;

  if (!initialized) {
    char *verbosity;

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
        fprintf(stderr,
                "voyant: unrecognized '%s' envvar value: '%s', should be one "
                "of 'warn', 'debug', or 'info'.\n",
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

__printf(2, 3) void ut_print(enum print_level level, const char *format, ...) {
  va_list args;
  int saved_errno;
  ut_print_fn_t print_fn;

  print_fn = __atomic_load_n(&__vy_pr, __ATOMIC_RELAXED);
  if (!print_fn)
    return;

  saved_errno = errno;
  va_start(args, format);
  __vy_pr(level, format, args);
  va_end(args);

  errno = saved_errno;
}

char *ut_strerror_r(int err, char *dst, int len) {
  int result = strerror_r(err < 0 ? -err : err, dst, len);
  if (result == -1)
    result = errno;

  if (result) {
    if (result == EINVAL)
      snprintf(dst, len, "unknown error (%d)", err < 0 ? err : -err);
    else
      snprintf(dst, len, "ERROR: strerror_r(%d)=%d", err, result);
  }

  return dst;
}

void *ut_add_mem(void **data, size_t *cap_cnt, size_t elem_sz, size_t cur_cnt,
                 size_t max_cnt, size_t add_cnt) {
  size_t new_cnt;
  void *new_data;

  if (cur_cnt + add_cnt <= *cap_cnt)
    return *data + cur_cnt * elem_sz;

  if (cur_cnt + add_cnt > max_cnt)
    return NULL;

  new_cnt = *cap_cnt;
  new_cnt += new_cnt / 4;
  if (new_cnt < 16)
    new_cnt = 16;
  if (new_cnt > max_cnt)
    new_cnt = max_cnt;
  if (new_cnt < cur_cnt + add_cnt)
    new_cnt = cur_cnt + add_cnt;

  new_data = ut_reallocarray(*data, new_cnt, elem_sz);
  if (!new_data)
    return NULL;

  memset(new_data + (*cap_cnt) * elem_sz, 0, (new_cnt - *cap_cnt) * elem_sz);

  *data = new_data;
  *cap_cnt = new_cnt;
  return new_data + cur_cnt * elem_sz;
}