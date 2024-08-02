probe sys_enter_socket{
	out("value: %d %d", pid(), cpu());
}
