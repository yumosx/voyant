#syscalls;

probe sys_exit_execve {
    exec[args->ret] |> count();
}