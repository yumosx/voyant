#bpf method
sudo bpftrace -l 'tracepoint:syscalls:*'

#execute fromat info
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format

#get trace_printk
sudo cat /sys/kernel/debug/tracing/trace_pipe
