#include <stdio.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <sched.h>
#include <sys/resource.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/perf_event.h>
#include <fcntl.h>
#include <unistd.h>

#include "annot.h" 
#include "ut.h"

#define LOG_BUF_SIZE 0x1000
char bpf_log_buf[LOG_BUF_SIZE];

static __u64 ptr_to_u64(const void* ptr) {
    return (__u64) (unsigned long) ptr;
}

long perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int bpf_prog_load(const struct bpf_insn* insns, int insn_cnt) {
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_TRACEPOINT,
        .insns = ptr_to_u64(insns),
        .insn_cnt = insn_cnt,
        .license = ptr_to_u64("GPL"),
        .log_buf = ptr_to_u64(bpf_log_buf),
        .log_size = LOG_BUF_SIZE,
        .log_level = 1,
        .kern_version = LINUX_VERSION_CODE,
    };
    
	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_map_create(enum bpf_map_type type, int ksize, int size, int entries) {
    union bpf_attr attr = {
       .map_type = type,
       .key_size = ksize,
       .value_size = size,
       .max_entries = entries,
    };

    return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

#define DEBUGFS "/sys/kernal/debug/tracing"

void read_trace_pipe(void) {
    int trace_fd;
    trace_fd = open(DEBUGFS, "trace_pipe", O_RDONLY, 0);
    
    if (trace_fd < 0)
        _errmsg("trace fd not found");

    while (1) {
        static char buf[4096];
        ssize_t sz;
        
        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz > 0) {
            buf[sz] = 0;
            puts(buf);
        }
    }
}

int tracepoint_setup(ebpf_t* e, int id) {
    struct perf_event_attr attr = {};
    
    int ed, bd;

    attr.type = PERF_TYPE_TRACEPOINT;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.config = id;  
    
    bd = bpf_prog_load(e->prog, e->ip - e->prog);
    
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
 
static int bpf_map_op(enum bpf_cmd cmd, int fd, void* key, void* val, int flags) {
	union bpf_attr attr = {
		.map_fd = fd,
		.key = ptr_to_u64(key),
		.value = ptr_to_u64(val),
		.flags = flags,
	};
	return syscall(__NR_bpf, cmd, &attr, sizeof(attr));
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