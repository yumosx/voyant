probe sys_enter_execve{
    out("[%s %s] %d", arg(0), comm(), pid());
}
