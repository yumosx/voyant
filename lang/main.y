probe sys_enter_open{
    map[comm()] := 1;
    a := 2;
    if (a > 1) {
        out("a: %d map: %d\n", a, map[comm()]);
    }
}
