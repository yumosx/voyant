#kprobe;

BEGIN{
    out("%s\n", "exit");
}

probe smp_call_function_many{
    out("%s\n", "----");
}
