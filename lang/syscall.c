#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/perf_event.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include "annot.h" 
#include "bpfsyscall.h"
#include "ut.h"

#define LOG_BUF_SIZE 0x1000
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


int read_field(char* name) {
    FILE* fmt;
    int offs;
    char line[0x80];

    fmt = fopenf("r", "/sys/kernel/debug/traceing/events/%s/format", name); 

    if (!fmt) {
        fclose(fmt);
        error("can't open the file");
        return;
    }
    
    char* save, *offs_s, *size_s, *sign_s;
    char* type_s, *str;


    while (fgets(line, sizeof(line), fmt)) {
        if (!strstr(line, "field:"))
            continue;

        type_s = strtok_r(line, ";", &save);
        offs_s = strtok_r(NULL, ";", &save);
        size_s = strtok_r(NULL, ";", &save);
        sign_s = strtok_r(NULL, ";", &save);

        type_s += sizeof("field:");
        
        printf("type: %s\n", type_s);
        offs_s += sizeof("offset:");
        printf("offs: %s\n", offs_s);
        size_s += sizeof("size:");
        sign_s += sizeof("signed:");
    }
    
    return 0;
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