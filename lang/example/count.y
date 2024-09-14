#syscalls;

BEGIN{
    out("%s\n", "Tracing sys_enter_open commands... Hit Ctrl-C to end.");
}

probe sys_enter_open{
    map[comm()] |> count();
}