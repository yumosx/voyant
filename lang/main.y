probe sys_enter_execve / comm() == "bash"/{
    printf("%s",comm());
}
