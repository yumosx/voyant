#kprobe;

probe oom_kill_process{
    oc := (oom_control*) arg1;
    out("%s", oc->filename);
}
