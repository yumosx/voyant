probe sys_enter_openat{
    map[cpu()] |> count();
}
