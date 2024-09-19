#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <bpf/btf.h>
#include <linux/bpf.h>
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

int bpf_test_attach(ebpf_t* e) {
    union bpf_attr attr;
    int id;
    
    memset(&attr, 0, sizeof(attr));
    id = bpf_prog_load(BPF_PROG_TYPE_RAW_TRACEPOINT, e->prog, e->ip-e->prog);    
    attr.test.prog_fd = id;

    return _bpf(BPF_PROG_TEST_RUN, &attr);
}

int bpf_kprobe_attach(ebpf_t* e, int id) {
    int bd;

    bd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, e->prog, e->ip - e->prog);
    return 0;
}


int bpf_probe_attach(ebpf_t* e, int id) {
    struct perf_event_attr attr = {};
    
    int ed, bd;

    attr.type = PERF_TYPE_TRACEPOINT;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.config = id;  
    
    bd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, e->prog, e->ip - e->prog);
    
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


int bpf_read_field(char* name, char* field) {
    FILE* fmt;
    int offs;
    char line[0x80];

    fmt = fopenf("r", "/sys/kernel/debug/tracing/events/%s/format", name); 

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

        type_s += sizeof("field:");
        
        offs_s += sizeof("offset:");
        size_s += sizeof("size:");
        sign_s += sizeof("signed:");

        if (type_s) {
            tname = rindex(type_s, ' ');
            *tname++ = '\0';

            if (vstreq(tname, field)) {
                int size;
                size = strtoul(offs_s, NULL, 0);
                return size;
            }
        }
    }
    
    return 0;
}

int bpf_get_probe_id(char* event, char* name) {
    char path[256];
    char* buffer;
    FILE* fp;
    int number;

    snprintf(path, sizeof(path), "%s/%s", event, name);


    buffer = vmalloc(256);
    sprintf(buffer, "/sys/kernel/debug/tracing/events/%s/id", path);
    
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
#ifdef libbpf
static struct btf* _btf = NULL;

int bpf_btf_setup() {
    _btf = btf__load_vmlinux_btf();
    if (!_btf)
        return bf_err_code(errno, "failed to load vmlinux BTF");
    return 0;
}

void bpf_btf_teardown() {
    btf__free(_btf);
    _btf = NULL;
}

int bpf_btf_get_id(const char* name) {
    int id;

    assert(name != NULL);
    id = btf__find_by_name(_btf, name);
    if (id < 0)
        return bf_err_code(errno, "failed to find BTF type for\"%s\"", name);
    
    return id;
}

int bpf_btf_get_filed_off(const char* struct_name, const char* field_name) {
    int offset = -1;
    int struct_id;
    struct btf_member* member;
    const struct btf_type* type;

    struct_id = btf__find_by_name_kind(_btf, struct_name, BTF_KIND_STRUCT);
}
#endif