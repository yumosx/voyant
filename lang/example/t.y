BEGIN {
    out("%s", "the unroll test");
}

probe sys_enter_execve {
    unroll(3) {
        out("%s\n", "1");
    }
    out("%s\n", "----------");
}
