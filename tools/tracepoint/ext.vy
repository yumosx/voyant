#ext4;

BEGIN {
    out("%-18s %-16s %-6s\n", "PID", "COMM", "LEN");
}

probe ext4_da_write_begin {
    arg := args->len;
    out("%-18d %-16s %-6d\n", pid(), comm(), arg);
}