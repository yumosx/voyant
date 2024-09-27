#syscalls;

probe sys_enter_renameat2{
    name := args->oldname;
    out("%s %s\n", comm(), name);
}