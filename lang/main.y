probe sys_enter_execve{
    out("[%s %s] %d", arg(1), comm(), pid());
}
