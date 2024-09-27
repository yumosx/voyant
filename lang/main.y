#syscalls;

BEGIN {
    out("%s\n", "Tracing sleeps. Hit Ctrl-C to end.");
}

probe sys_enter_execve{
    out("-->%s\n", comm());
}

probe sys_exit_execve{
    out("<--%s\n", comm());
}
