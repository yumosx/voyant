#syscalls;

probe sys_enter_execve{
    map[pid()] |> count();
}
