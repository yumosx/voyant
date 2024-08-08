probe sys_enter_socket{
    a = 12;
    out("v: %d %d", a, pid());
}
