probe sys_enter_execve{
    map[pid()] = 1;
    out("name: %s, count: %d", comm(), map[pid()]);
}
