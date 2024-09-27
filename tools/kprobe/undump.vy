#kprobe;

BEGIN{
    out("%s\n", "attach unix_stream_read_actor");
}

probe unix_stream_read_actor{
    out("%s\n", comm());
}