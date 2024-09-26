#syscalls;

probe sys_exit_execve{
    arg := args->ret;
    out("%s", arg);
}