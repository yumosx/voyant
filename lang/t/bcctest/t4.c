BPF_PERF_OUTPUT(output);

struct data_t
{
    int pid;
    int uid;
    char command[16];
    char message[12];
};

int hello(void* ctx) {
    struct data_t data = {};
    char message[12] = "Hello, World";

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = buf_get_curretn_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_kernal(&data.message, sizeof(data.message), ,message);

    output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
