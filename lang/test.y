#kprobe;

probe do_mmap{
    out("->enter: %s\n", comm());
}
