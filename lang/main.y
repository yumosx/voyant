#syscalls;

probe sys_enter_execve {
    enter[pid()] := comm();
    out("%s\n", args->filename);
}

probe sys_exit_execve{
    ext[pid()] := comm();
}
