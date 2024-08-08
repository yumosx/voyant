probe sys_enter_socket{
    out("v: %d %d", cpu(), pid());
}
