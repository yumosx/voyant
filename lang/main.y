#syscalls;

BEGIN {
    out("%s\n", "Tracing sleeps. Hit Ctrl-C to end.");
}

probe sys_enter_connect{
    a := pid();
    out("-> connect() by (%s) PID %d\n", comm(), a);
}
