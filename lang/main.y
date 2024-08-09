probe sys_enter_socket{
    out("cpu: %d, pid: %d", cpu(), pid());
}
