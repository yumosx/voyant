#syscalls;

probe sys_enter_execve{
    map[comm()] |> count();
}
