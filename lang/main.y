#syscalls;

probe sys_enter_nanosleep{
    map[comm()] |> count();
}
