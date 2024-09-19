#syscalls;

BEGIN {
    out("%s\n", "Tracing sleeps. Hit Ctrl-C to end.");
}

probe sys_enter_connect{
    out("-> connect() by %s PID %d\n", comm(), pid());
}
