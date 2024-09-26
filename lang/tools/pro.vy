#syscalls;

probe sys_exit_execve {
    ret := args->ret;
    out("%s %d\n", comm(), ret);
}