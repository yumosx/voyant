probe sys_enter_open{
    map[comm()] |> count();
}
