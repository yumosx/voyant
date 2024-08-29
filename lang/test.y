BEGIN {
    out("%s\n", "map count");
}

probe sys_enter_open {
    map[comm()] |> count();
}
