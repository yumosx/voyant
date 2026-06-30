#syscalls;

BEGIN{
    out("%-18s %-16s %-6s %s\n", "PID", "COMM", "FD", "PATH");
}

probe sys_enter_open {
    enter[pid()] := args->filename;
}

probe sys_exit_open {
    ret := args->ret;
    out("%-18d %-16s %-6d %s\n", pid(), comm(), ret, enter[pid()]);
}
