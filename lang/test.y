#syscalls;


probe sys_exit_clone{
   a := args->prev_state;
}
