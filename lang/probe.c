#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <byteswap.h>
#include <sys/param.h>
#include <linux/btf.h>
#include <linux/bpf.h>
#include <sys/utsname.h>
#include <linux/version.h>
#include <linux/perf_event.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include "annot.h" 
#include "probe.h"
#include "ut.h"

#define LOG_BUF_SIZE 1 << 20
char bpf_log_buf[LOG_BUF_SIZE];

static __u64 ptr_to_u64(const void* ptr) {
    return (__u64) (unsigned long) ptr;
}

int _bpf(enum bpf_cmd cmd, union bpf_attr *attr) {
    int r = (int) syscall(__NR_bpf, cmd, attr, sizeof(*attr));
    if (r < 0)
        return -errno;
    return r;
}

long perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn* insns, int insn_cnt) {
    union bpf_attr attr = {
        .prog_type = type,
        .insns = ptr_to_u64(insns),
        .insn_cnt = insn_cnt,
        .license = ptr_to_u64("GPL"),
        .log_buf = ptr_to_u64(bpf_log_buf),
        .log_size = LOG_BUF_SIZE,
        .log_level = 1,
        .kern_version = LINUX_VERSION_CODE, 
    };

    return _bpf(BPF_PROG_LOAD, &attr);
}


int bpf_map_create(enum bpf_map_type type, int ksize, int size, int entries) {
    union bpf_attr attr = {
       .map_type = type,
       .key_size = ksize,
       .value_size = size,
       .max_entries = entries,
    };

    return _bpf(BPF_MAP_CREATE, &attr);
}

int bpf_test_attach(ebpf_t* ctx) {
    union bpf_attr attr;
    int id;
    
    memset(&attr, 0, sizeof(attr));
    id = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT, ctx->prog, ctx->ip-ctx->prog);    
    attr.test.prog_fd = id;

    return _bpf(BPF_PROG_TEST_RUN, &attr);
}


int bpf_kprobe_attach(ebpf_t* ctx, int id) {
    struct perf_event_attr attr = {};
    
    int ed, bd;

    attr.type = PERF_TYPE_TRACEPOINT;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.config = id;  
    
    bd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, ctx->prog, ctx->ip - ctx->prog);
    
    if (bd < 0) {
        perror("bpf");
        fprintf(stderr, "bpf verifier:\n%s\n", bpf_log_buf);
        return 1;
    }
    
    ed = perf_event_open(&attr, -1, 0, -1, 0);

    if (ed < 0){
        perror("perf_event_open");
        return 1;
    }
    
    if (ioctl(ed, PERF_EVENT_IOC_ENABLE, 0)) {
        perror("perf enable");
        return 1;
    }

    if (ioctl(ed, PERF_EVENT_IOC_SET_BPF, bd)) {
        perror("perf attach");
        return 1;
    } 

    return 0;
}


int bpf_probe_attach(ebpf_t* ctx, int id) {
    struct perf_event_attr attr = {};
    
    int ed, bd;

    attr.type = PERF_TYPE_TRACEPOINT;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.config = id;  
    
    bd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, ctx->prog, ctx->ip - ctx->prog);
    
    if (bd < 0) {
        perror("bpf");
        fprintf(stderr, "bpf verifier:\n%s\n", bpf_log_buf);
        return 1;
    }
    
    ed = perf_event_open(&attr, -1, 0, -1, 0);

    if (ed < 0){
        perror("perf_event_open");
        return 1;
    }
    
    if (ioctl(ed, PERF_EVENT_IOC_ENABLE, 0)) {
        perror("perf enable");
        return 1;
    }

    if (ioctl(ed, PERF_EVENT_IOC_SET_BPF, bd)) {
        perror("perf attach");
        return 1;
    } 

    return 0;
}

static int profile_perf_event_open(profile_t* profile, int cpu, int freq) {
    struct perf_event_attr attr = {};
    int err = 0, i = profile->num, bd;

    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.freq = 1;
    attr.sample_freq = freq;

    profile->efds[i] = perf_event_open(&attr, -1, cpu, -1, 0);

    if (profile->efds[i] < 0) {
        return -errno;
    }

    if (ioctl(profile->efds[i], PERF_EVENT_IOC_ENABLE, 0)) {
        close(profile->efds[i]);
        return -errno;
    }

    profile->num++;
    return 0;
}

void profile_attach(ebpf_t* code) {
    int ncpus;
    profile_t* profile;

    ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    profile = vcalloc(1, sizeof(*profile));
}


type_t get_filed_type(char* name, unsigned long size, unsigned long sign) {
    int s = 1;

    if (!strncmp(name, "signed ", sizeof("signed"))){
		name += sizeof("signed");
	} else if (!strncmp(name, "unsigned ", sizeof("unsigned"))){
		name += sizeof("unsigned");
    } else{
		s = 0;
    }

    if (!strcmp(name, "int") || !strcmp(name, "long")) {
        return TYPE_INT;
    } else if(!strcmp(name, "const char *")) {
        return TYPE_STR;
    } else {
        return TYPE_NULL;
    }
}

int arch_reg_width(void) {
    return sizeof(uint64_t);
}

int bpf_read_field(field_t* field) {
    FILE* fmt;
    unsigned long offs, size, sign, len = 0;
    char line[0x80];

    fmt = fopenf("r", "/sys/kernel/debug/tracing/events/%s/format", field->name); 

    if (!fmt) {
        fclose(fmt);
        error("can't open the file");
        return;
    }
    
    char* save, *offs_s, *size_s, *sign_s;
    char* type_s, *str, *tname;


    while (fgets(line, sizeof(line), fmt)) {
        if (!strstr(line, "field:"))
            continue;

        type_s = strtok_r(line, ";", &save);
        offs_s = strtok_r(NULL, ";", &save);
        size_s = strtok_r(NULL, ";", &save);
        sign_s = strtok_r(NULL, ";", &save);

        if (!(type_s && offs_s && size_s && sign_s)) {
            _e("read type_s, off_s error");
        }

        type_s += sizeof("field:");
        offs_s += sizeof("offset:");
        size_s += sizeof("size:");
        sign_s += sizeof("signed:");

        offs = strtol(offs_s, NULL, 0);
        size = strtoul(size_s, NULL, 0);
        sign = strtoul(sign_s, NULL, 0);

        if (!type_s) {
            _e("type not found");
        }

        tname = rindex(type_s, ' ');
        *tname++ = '\0';

        if (!strcmp(tname, field->field)) {
            field->offs = offs;
            field->type = get_filed_type(type_s, size, sign);
            return 0;
        }
    }

    return 0;
}

int bpf_get_probe_id(char* name) {
    char* buffer;
    FILE* fp;
    int number;

    buffer = vmalloc(256);
    sprintf(buffer, "/sys/kernel/debug/tracing/events/%s/id", name);
    
    fp = fopen(buffer, "r");

    if (fp == NULL) {
        verror("Error opening file");
        return 1;
    }

    if (fscanf(fp, "%d", &number) != 1) {
        fprintf(stderr, "Error reading number from file\n");
        fclose(fp);
        return 1;
    }
    
    free(buffer);
    return number;
}

int bpf_get_kprobe_id(char* func) {
    FILE* fp;
    char str[128];

	sprintf(str, "echo 'p %s' >/sys/kernel/debug/tracing/kprobe_events", func);
	system(str);

    sprintf(str, "/sys/kernel/debug/tracing/events/kprobes/p_%s_0/id", func);
    fp = fopen(str, "r");
    if (!fp)
        return -1;
    
    fgets(str, sizeof(str), fp);
    fclose(fp);

    return strtol(str, NULL, 0);
}

static int bpf_map_op(enum bpf_cmd cmd, int fd, void* key, void* val, int flags) {
	union bpf_attr attr = {
		.map_fd = fd,
		.key = ptr_to_u64(key),
		.value = ptr_to_u64(val),
		.flags = flags,
	};
    
    return _bpf(cmd, &attr);
}

int bpf_map_lookup(int fd, void* key, void* val) {
	return bpf_map_op(BPF_MAP_LOOKUP_ELEM, fd, key, val, 0);
}

int bpf_map_update(int fd, void* key, void* val, int flags) {
	return bpf_map_op(BPF_MAP_UPDATE_ELEM, fd, key, val, flags);
}

int bpf_map_next(int fd, void* key, void* next_key) {
    return bpf_map_op(BPF_MAP_GET_NEXT_KEY, fd, key, next_key, 0);
}

int bpf_map_delete(int fd, void* key, void* val) {
	return bpf_map_op(BPF_MAP_DELETE_ELEM, fd, key, val, 0);
}

int bpf_map_close(int fd){
    close(fd);
}

int perf_event_enable(int id) {
    if (ioctl(id, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP)) {
        return -1;
    }
    return 0;
}

static void btf_bswap_hdr(struct btf_header *h) {
	h->magic = bswap_16(h->magic);
	h->hdr_len = bswap_32(h->hdr_len);
	h->type_off = bswap_32(h->type_off);
	h->type_len = bswap_32(h->type_len);
	h->str_off = bswap_32(h->str_off);
	h->str_len = bswap_32(h->str_len);
}

static int btf_parse_hdr(btf_t *btf) {
	struct btf_header *hdr = btf->hdr;
	__u32 meta_left;

	if (btf->raw_size < sizeof(struct btf_header)) {
		_pr_debug("BTF header not found\n");
		return -EINVAL;
	}

	if (hdr->magic == bswap_16(BTF_MAGIC)) {
		btf->swapped_endian = true;
		if (bswap_32(hdr->hdr_len) != sizeof(struct btf_header)) {
			_pr_warn("Can't load BTF with non-native endianness due to unsupported header length %u\n",
				bswap_32(hdr->hdr_len));
			return -ENOTSUP;
		}
		btf_bswap_hdr(hdr);
	} else if (hdr->magic != BTF_MAGIC) {
		_pr_debug("Invalid BTF magic: %x\n", hdr->magic);
		return -EINVAL;
	}

	if (btf->raw_size < hdr->hdr_len) {
		_pr_debug("BTF header len %u larger than data size %u\n",
			 hdr->hdr_len, btf->raw_size);
		return -EINVAL;
	}

	meta_left = btf->raw_size - hdr->hdr_len;
	if (meta_left < (long long)hdr->str_off + hdr->str_len) {
		_pr_debug("Invalid BTF total size: %u\n", btf->raw_size);
		return -EINVAL;
	}

	if ((long long)hdr->type_off + hdr->type_len > hdr->str_off) {
		_pr_debug("Invalid BTF data sections layout: type data at %u + %u, strings data at %u + %u\n",
			 hdr->type_off, hdr->type_len, hdr->str_off, hdr->str_len);
		return -EINVAL;
	}

	if (hdr->type_off % 4) {
		_pr_debug("BTF type section is not aligned to 4 bytes\n");
		return -EINVAL;
	}

	return 0;
}



__u32 btf__type_cnt(const btf_t* btf) {
    return btf->start_id + btf->nr_types;
}

static int btf_parse_str_sec(btf_t *btf) {
	const struct btf_header *hdr = btf->hdr;
	const char *start = btf->strs_data;
	const char *end = start + btf->hdr->str_len;

	if (btf->base_btf && hdr->str_len == 0)
		return 0;
	if (!hdr->str_len || hdr->str_len - 1 > BTF_MAX_STR_OFFSET || end[-1]) {
		_pr_debug("Invalid BTF string section\n");
		return -EINVAL;
	}
	if (!btf->base_btf && start[0]) {
		_pr_debug("Invalid BTF string section\n");
		return -EINVAL;
	}
	return 0;
}

static void btf_bswap_type_base(struct btf_type *t) {
	t->name_off = bswap_32(t->name_off);
	t->info = bswap_32(t->info);
	t->type = bswap_32(t->type);
}


static int btf_type_size(const struct btf_type *t) {
	const int base_size = sizeof(struct btf_type);
	__u16 vlen = btf_vlen(t);

	switch (btf_kind(t)) {
	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
		return base_size;
	case BTF_KIND_INT:
		return base_size + sizeof(__u32);
	case BTF_KIND_ENUM:
		return base_size + vlen * sizeof(struct btf_enum);
	case BTF_KIND_ARRAY:
		return base_size + sizeof(struct btf_array);
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return base_size + vlen * sizeof(struct btf_member);
	case BTF_KIND_FUNC_PROTO:
		return base_size + vlen * sizeof(struct btf_param);
	case BTF_KIND_VAR:
		return base_size + sizeof(struct btf_var);
	case BTF_KIND_DATASEC:
		return base_size + vlen * sizeof(struct btf_var_secinfo);
	default:
		_pr_debug("Unsupported BTF_KIND:%u\n", btf_kind(t));
		return -EINVAL;
	}
}

static int btf_bswap_type_rest(struct btf_type *t)
{
	struct btf_var_secinfo *v;
	struct btf_enum64 *e64;
	struct btf_member *m;
	struct btf_array *a;
	struct btf_param *p;
	struct btf_enum *e;
	__u16 vlen = btf_vlen(t);
	int i;

	switch (btf_kind(t)) {
	case BTF_KIND_FWD:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_PTR:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
		return 0;
	case BTF_KIND_INT:
		*(__u32 *)(t + 1) = bswap_32(*(__u32 *)(t + 1));
		return 0;
	case BTF_KIND_ENUM:
		for (i = 0, e = btf_enum(t); i < vlen; i++, e++) {
			e->name_off = bswap_32(e->name_off);
			e->val = bswap_32(e->val);
		}
		return 0;
	case BTF_KIND_ARRAY:
		a = btf_array(t);
		a->type = bswap_32(a->type);
		a->index_type = bswap_32(a->index_type);
		a->nelems = bswap_32(a->nelems);
		return 0;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		for (i = 0, m = btf_members(t); i < vlen; i++, m++) {
			m->name_off = bswap_32(m->name_off);
			m->type = bswap_32(m->type);
			m->offset = bswap_32(m->offset);
		}
		return 0;
	case BTF_KIND_FUNC_PROTO:
		for (i = 0, p = btf_params(t); i < vlen; i++, p++) {
			p->name_off = bswap_32(p->name_off);
			p->type = bswap_32(p->type);
		}
		return 0;
	case BTF_KIND_VAR:
		btf_var(t)->linkage = bswap_32(btf_var(t)->linkage);
		return 0;
	case BTF_KIND_DATASEC:
		for (i = 0, v = btf_var_secinfos(t); i < vlen; i++, v++) {
			v->type = bswap_32(v->type);
			v->offset = bswap_32(v->offset);
			v->size = bswap_32(v->size);
		}
		return 0;
	default:
		_pr_debug("Unsupported BTF_KIND:%u\n", btf_kind(t));
		return -EINVAL;
	}
}

static void *btf_add_type_offs_mem(btf_t *btf, size_t add_cnt) {
	return ut_add_mem((void **)&btf->type_offs, &btf->type_offs_cap, sizeof(__u32),
			      btf->nr_types, BTF_MAX_NR_TYPES, add_cnt);
}

static int btf_add_type_idx_entry(btf_t* btf, __u32 type_off) {
    __u32* p;
    
    p = btf_add_type_offs_mem(btf, 1);
	if (!p)
		return -ENOMEM;

	*p = type_off;
	return 0;
}


static int btf_parse_type_sec(btf_t *btf) {
	struct btf_header *hdr = btf->hdr;
	void *next_type = btf->types_data;
	void *end_type = next_type + hdr->type_len;
	int err, type_size;

	while (next_type + sizeof(struct btf_type) <= end_type) {
		if (btf->swapped_endian)
			btf_bswap_type_base(next_type);

		type_size = btf_type_size(next_type);
		if (type_size < 0)
			return type_size;
		if (next_type + type_size > end_type) {
			_pr_warn("BTF type [%d] is malformed\n", btf->start_id + btf->nr_types);
			return -EINVAL;
		}

		if (btf->swapped_endian && btf_bswap_type_rest(next_type))
			return -EINVAL;

		err = btf_add_type_idx_entry(btf, next_type - btf->types_data);
		if (err)
			return err;

		next_type += type_size;
		btf->nr_types++;
	}

	if (next_type != end_type) {
		_pr_warn("BTF types data is malformed\n");
		return -EINVAL;
	}

	return 0;
}


static bool btf_is_modifiable(const btf_t *btf)
{
	return (void *)btf->hdr != btf->raw_data;
}


void btf_free(btf_t* btf) {
    if (IS_ERR_OR_NULL(btf)) {
        return;
    }

    if (btf->fd >= 0)
        close(btf->fd);

    if (btf_is_modifiable(btf)) {
        free(btf->hdr);
        free(btf->types_data);
    }

    free(btf->raw_data);
    free(btf->raw_data_swapped);
    free(btf->type_offs);

    if (btf->owns_base)
        btf_free(btf->base_btf);

    free(btf);
}


static btf_t* btf_new(const void* data, __u32 size, btf_t* base_btf) {
    btf_t* btf;
    int err;

    btf = calloc(1, sizeof(struct btf_t));
    if (!btf)
        return ERR_PTR(-ENOMEM);

    btf->nr_types = 0;
    btf->start_id = 1;
    btf->start_str_off = 0;
    btf->fd = -1;

    if (base_btf) {
        btf->base_btf = base_btf;
        btf->start_id = btf__type_cnt(base_btf);
        btf->start_str_off = base_btf->hdr->str_len;
    }

    btf->raw_data = malloc(size);
    if (!btf->raw_data) {
        err = -ENOMEM;
        goto done;
    }
    memcpy(btf->raw_data, data, size);
    btf->raw_size = size;
    btf->hdr = btf->raw_data;

    err = btf_parse_hdr(btf);
    if (err)
        goto done;
    
    btf->strs_data = btf->raw_data + btf->hdr->hdr_len + btf->hdr->str_off;
    btf->types_data = btf->raw_data + btf->hdr->hdr_len + btf->hdr->type_off;

    err = btf_parse_str_sec(btf);
    err = err? : btf_parse_type_sec(btf);
    if (err)
        goto done;
done:
    if (err) {
        btf_free(btf);
        return ERR_PTR(err);
    }

    return btf;
}

btf_t* btf_parse_raw(const char* path) {
    btf_t* btf = NULL;
    void* data = NULL;
    FILE* file = NULL;
    __u16 magic;
    int err = 0;
    long sz;

    file = fopen(path, "rbe");
    if (!file) {
        err = -errno;
        goto err_out;
    }

    if (fread(&magic, 1, sizeof(magic), file) < sizeof(magic)) {
        err = -EIO;
        goto err_out;
    }

    if (magic != BTF_MAGIC) {
        err = -EPROTO;
        goto err_out;
    }

    if (fseek(file, 0, SEEK_END)) {
        err = -errno;
        goto err_out;
    }

    sz = ftell(file);
    if (sz < 0) {
        err = -errno;
        goto err_out;
    }

    if (fseek(file, 0, SEEK_SET)) {
        err = -errno;
        goto err_out;
    }

    data = malloc(sz);
    if (!data) {
        err = -ENOMEM;
        goto err_out;
    }

    if (fread(data, 1, sz, file) < sz) {
        err = -EIO;
        goto err_out;
    }
    btf = btf_new(data, sz, NULL);
err_out:
    free(data);
    if (file) {
        fclose(file);
    }
    return err ? ERR_PTR(err) : btf;
}

static btf_t* btf_parse(const char* path) {
    struct btf_t* btf;
    int err = 0;

    btf = btf_parse_raw(path);
    err = get_error(btf);
    if (!err)
        return btf;

    if (err != -EPROTO)
        return ERR_PTR(err);
}

static struct btf_t* vy_btf__parse(const char* path) {
    return ut_err(btf_parse(path));
}


btf_t* btf_load_vmlinux() {
    const char* sysfs_btf_path = "/sys/kernel/btf/vmlinux";
    char path[PATH_MAX+1];

    struct utsname buf;
	struct btf *btf;
	int i, err;

	if (faccessat(AT_FDCWD, sysfs_btf_path, F_OK, AT_EACCESS) < 0) {
		_pr_warn("kernel BTF is missing at '%s', was CONFIG_DEBUG_INFO_BTF enabled?\n",
			sysfs_btf_path);
	} else {
		btf = vy_btf__parse(sysfs_btf_path);
		if (!btf) {
			err = -errno;
			_pr_warn("failed to read kernel BTF from '%s': %d\n", sysfs_btf_path, err);
			return NULL;
		}
		_pr_debug("loaded kernel BTF from '%s'\n", sysfs_btf_path);
		return btf;
	}
}


struct btf_type* btf_type_by_id(const btf_t* btf, __u32 type_id) {
    if (type_id == 0)
        return ;
    if (type_id < btf->start_id)
        return btf_type_by_id(btf->base_btf, type_id);
    
    return btf->types_data + btf->type_offs[type_id-btf->start_id]; 
}

const struct btf_type* btf__type_by_id(btf_t* btf, __u32 type_id) {
    if (type_id >= btf->start_id + btf->nr_types)
        return errno = EINVAL, NULL;
    
    return btf_type_by_id(btf, type_id);
}

static const void* btf_strs_data(const btf_t* btf)
{
    return btf->strs_data ? btf->strs_data : NULL;
}


const char* btf__str_by_offset(const btf_t* btf, __u32 offset) {
    if (offset < btf->start_str_off) {
        return btf__str_by_offset(btf->base_btf, offset);   
    } else if (offset - btf->start_str_off < btf->hdr->str_len) {
        return btf_strs_data(btf) + (offset - btf->start_str_off);
    } else {
        return errno = EINVAL, NULL;
    }
}

const char* btf__name_by_offset(const btf_t* btf, __u32 offset) {
    return btf__str_by_offset(btf, offset);
}

static __s32 btf_find_by_name_kind(
    const struct btf* btf, int start_id, const char* type_name, __u32 kind) 
{
    __u32 i, nr_types = btf__type_cnt(btf);
    if (kind == BTF_KIND_UNKN || !strcmp(type_name, "void")) {
        return 0;
    }

    for (i = start_id; i < nr_types; i++) {
        const struct btf_type* type = btf__type_by_id(btf, i);
        const char* name;

        if (btf_kind(type) != kind) {
            continue;
        }

        name = btf__name_by_offset(btf, type->name_off);
        
        if (name && !strcmp(type_name, name))
            return i;
    }

    return libbpf_err(-ENOENT);
}

__s32 btf__find_by_name_kind(const struct btf *btf, const char *type_name, __u32 kind) {
	return btf_find_by_name_kind(btf, 1, type_name, kind);
}

int btf_get_field_off(const char *struct_name, const char *field_name) {
    int offset = -1;
    int struct_id;
    struct btf_member *member;
    const struct btf_type *type;
    btf_t* btf;

    btf = btf_load_vmlinux();

    struct_id = btf__find_by_name_kind(btf, struct_name, BTF_KIND_STRUCT);
    if (struct_id < 0) {
        verror("can't find structure %s", struct_name);
    }
    type = btf__type_by_id(btf, struct_id);
    if (!type)
        verror("can t get btf_type for %s", struct_name);

    member = (struct btf_member *)(type + 1);
    for (size_t i = 0; i < BTF_INFO_VLEN(type->info); ++i, ++member) {
        const char *cur_name = btf__name_by_offset(btf, member->name_off);
        if (!cur_name || !vstreq(cur_name, field_name))
            continue;

        if (BTF_INFO_KFLAG(type->info))
            offset = BTF_MEMBER_BIT_OFFSET(member->offset);
        else
            offset = member->offset;

        break;
    }

    if (offset < 0 || offset % 8)
        return -ENOENT;

    return offset / 8;
}