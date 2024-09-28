#kprobe;

probe filemap_fault{
    map[comm()] |> count();
    out("%s\n", comm());
}