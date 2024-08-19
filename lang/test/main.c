#define ARGSIZE 64
#define TOTAL_MAX_ARGS 5
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)


TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    
    const char** argv;
    int pid = pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    argv = (const char**)(args->argv);
}