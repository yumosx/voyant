probe sys_enter_openat2 /comm() == "bash"/{
    printf("%s", comm());
}
