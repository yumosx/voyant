int main() {
    bpf_trace_printk("%d", bpf_get_current_pid_tgid());
    return 0;
}
