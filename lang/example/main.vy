BEGIN {
    out("%-18s %-16s %-6s\n", "PID", "COMM", "FILE");
}

probe sys_enter_execve {
    out("%-18d %-16s %-6s\n", pid(), comm(), arg());
}

#syscalls;
probe sys_enter_kill{
    out("%s\n", comm());
    map[comm()] |> count();
}

probe sys_enter_nanosleep{
    out("%s\n", comm());
}

probe sys_enter_statfs{
    out("%s\n", comm());
}

probe sys_enter_setuid{
    map[comm()] |> count();
}

#skb;
probe kfree_skb {
    out("%s\n", comm());
}

#sched;
probe sched_process_fork {
	map[comm()] |> count();
}


kprobe cap_capable {
    out("%s\n", comm());
}

kprobe oom_kill_process {
    out("%s\n", comm());
}