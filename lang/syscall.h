#ifndef SYSCALL_H
#define SYSCALL_H


int bpf_map_create(enum bpf_map_type type, int key_sz, int val_sz, int entries);
int bpf_map_update(int fd, void* key, void* val, int flags);

#endif
