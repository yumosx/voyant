probe sys_enter_execve{
	printf("%s", comm());
}
