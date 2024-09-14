#syscalls;


probe sys_enter_open {
    a := 1;
    out("%d\n", a);
    a = 2;
    out("%d\n", a);
}
