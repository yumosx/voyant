#syscalls;

BEGIN {
    out("%-18s %-16s %-14s %-12s\n", "PID", "COMM", "LEN", "FD");
}

probe sys_enter_mmap {
    len := args->len;
    fd  := args->fd;

    out("%-18d %-16s %-14d %-12d\n", pid(), comm(), len, fd);
}