#exceptions;

BEGIN {
    out("%-18s %-16s\n", "PID", "COMM");
}

probe page_fault_user{
    map[comm()] |> count();
    out("%-18d %-16s\n", pid(), comm());
}