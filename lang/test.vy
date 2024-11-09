#syscalls;

probe sys_enter_execve{
    out("%s\n", args->filename);
}
