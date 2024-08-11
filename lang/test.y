probe sys_enter_execve {
   map[1].count();
   out("%d\n", map[1]); 
}