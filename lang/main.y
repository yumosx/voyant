BEGIN {
    out("%-18s %-16s %-6s\n", "PID", "COMM", "FILE");
}

probe sys_enter_open {
    out("%-18d %-16s %-6s\n", pid(), comm(), arg());
}
