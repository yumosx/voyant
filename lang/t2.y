BEGIN {
    out("%s\n", "----------------");
}

probe sys_enter_open {
    map[comm()] |> count();
}
