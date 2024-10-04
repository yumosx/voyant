#syscalls;

probe sys_enter_execve{
    a := 1;
    if (a == 1) {
        out("%d\n", 2 / 2);
    }
}
