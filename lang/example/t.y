BEGIN {
    out("%s\n", "the unroll test");
}

probe sys_enter_execve {
    unroll(8) {
        out("%s\n", "1");
    }
    out("%s\n", "----------");
}
