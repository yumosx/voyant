#syscalls;

probe sys_enter_execve {
    out("%d\n", 1+2);
}

probe sys_exit_execve {
    out("%d\n", 1+2+3);
}
