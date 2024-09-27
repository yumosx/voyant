#syscalls;

probe sys_enter_statfs {
    p := args->pathname;
    out("%s\n", p);
}