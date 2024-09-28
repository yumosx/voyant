#syscalls;

BEGIN {
    out("%s\n", "Tracing sleeps. Hit Ctrl-C to end.");
}

probe sys_enter_execve {
    map[pid()] := 12;
}

probe sys_exit_execve{
    a := args->ret;
    out("%d\n", a);
}
