probe sys_enter_execve{
    map[comm()] |> count();
    out("name: %-16s %6d", comm(), map[comm()]);
}