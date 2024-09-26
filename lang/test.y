#syscalls;

probe sys_enter_execve/strcmp("sh", "sh")/ {
    out("%s\n", "hello");
}
