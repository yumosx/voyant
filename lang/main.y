probe sys_enter_socket{
    map[1] = 2;
    out("name: %d %d", pid(), map[1]);
}
