#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <bpf/btf.h>
#include <linux/bpf.h>
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

btf_t* btf_parse_raw(const char* path) {
    struct btf* btf = NULL;
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

err_out:
    free(data);
    if (file) {
        fclose(file);
    }
    return err ? ERR_PTR(err) : btf;
}

__u32 btf__type_cnt(const btf_t* btf) {
    return btf->start_id + btf->nr_types;
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
done:
    if (err) {
        //btf__free(btf);
        return ERR_PTR(err);
    }

    return btf;
}

btf_t* btf_load_vmlinux(const char* path) {
    const char* sysfs_btf_path = "sys/kernel/btf/vmlinux";
}