probe sys_enter_execve{
     a = pid();
     printf("%d\n", a);
     printf("%s", comm());
}
