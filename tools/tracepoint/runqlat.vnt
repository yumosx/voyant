#sched;

BEGIN{
    out("tracing cpu scheduler ...");
}

probe sched_wakeup{
    
    out("%d\n", args->pid);
}