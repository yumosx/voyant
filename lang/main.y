#kprobe;

probe do_mmap {
    out("%d\n", 1+2+3);
}
