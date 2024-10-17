#syscalls;

//buffer := (struct sk_buff*) args->xxx;
probe sys_enter_execve{
    a := 4 * 2;
    b := 4 + 2;
    c := 4 - 2;
    d := 4 / 2;

    if (a <= 8) {
        out("a <= %d\n", 8);
    }

    if (a >= 8) {
        out("a >= %d\n", 8);
    }


    out("a:%d b:%d c:%d d:%d\n", a, b, c, d);
}
