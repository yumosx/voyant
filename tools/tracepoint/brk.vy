#syscalls;

BEGIN {
    out("%-18s %-16s\n", "PID", "COMM");
}

probe sys_enter_brk {
    map[comm()] |> count();
    out("%-18d %-16s\n", pid(), comm());
}