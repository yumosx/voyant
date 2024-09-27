## cpu篇章


## 内存篇

### mmap

```c
void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset);
```
- 参数start：指向欲映射的内存起始地址，通常设为 NULL，代表让系统自动选定地址，映射成功后返回该地址。
- 参数length：代表将文件中多大的部分映射到内存。
- 参数prot: 映射区域的保护方式。可以为以下几种方式的组合。
- 参数flags：影响映射区域的各种特性。在调用mmap()时必须要指定MAP_SHARED 或MAP_PRIVATE。
- 参数fd：要映射到内存中的文件描述符.
- 参数offset：文件映射的偏移量，通常设置为0，代表从文件最前方开始对应，offset必须是分页大小的整数倍。

```c
#syscalls;

BEGIN {
    out("%-18s %-16s %-6s\n", "PID", "COMM", "LEN");
}

probe sys_enter_mmap {
    arg := args->len;
    out("%-18d %-16s %-6d\n", pid(), comm(), arg);
}
```


### sys_enter_brk

应用程序的数据存放于堆内存中, 堆内存通过 brk(2) 系统 调 用 进行 扩 展。 
跟踪brk(2)调用，并且展示导致增长的用户态调用栈信息相对来说是很有用的分析信息。 
同时还有一个sbrk(2)变体调用。在Linux 中，sbrk(2)是以库函数形式实现的，内部仍 然使用brk(2)系统调用。

brk(2)这个系统调用可以使用 sys_enter_brk 这个函数来进行跟踪

```c
#syscalls;

BEGIN {
    out("%-18s %-16s\n", "PID", "COMM");
}

probe sys_enter_brk {
    map[comm()] |> count();
    out("%-18d %-16s\n", pid(), comm());
}
```

### vmscan

vmscan(8) 使用vmscan 跟踪点来观 察页换出守护进程(kswapd)的操作，该进程在系统内存压力上升时负责释放内存以便重用。

### page_fault_user

使用下面这个程序, 我们可以检测用户态的page fault

```c
#exceptions;

BEGIN {
    out("%-18s %-16s\n", "PID", "COMM");
}

probe page_fault_user{
    map[comm()] |> count();
    out("%-18d %-16s\n", pid(), comm());
}
```

## 文件系统

### ext4_da_write_begin

```c
#ext4;

BEGIN {
    out("%-18s %-16s %-6s\n", "PID", "COMM", "LEN");
}

probe ext4_da_write_begin {
    arg := args->len;
    out("%-18d %-16s %-6d\n", pid(), comm(), arg);
}
```

### sys_enter_open

```c
#syscall;

probe sys_enter_open {
    arg := args->filename;

    out("%s\n", arg);
}
```

### sys_enter_sync

这个函数可以用来检测sync这个系统调用,  sync(2)的作用是将修改过的数据写回磁盘
```c
#syscall;

probe sys_enter_sync {
    out("%s\n", comm());
}
```

### sys_enter_read

文件描述符到文件名称的转化, 

- 通过tasks truct找到文件描述符表，同时利用FD作为索引值找到对应的file结构体。 文件名称可以从这个结构体中读取 。 scread(2) 用的就是这种方法。 不过这种方法并不十分稳定:找到文件描述符表的方式(task->files- >fdt->fd)利用了 内核中的一些内部实现 细节，每个内核版本都不一定一样，所以这会导致该脚本无法跨版本使用。

- 通过跟踪open(2)系统调 构造一个以PID和FD为键的哈希表，值为对应的文件名和路径名 。 这样就可以在处理 read(2 )以及其他系统调用的时候进行查询了。虽然 这样增加了一个额外的探针( 带来 了额外 的性 能消耗)，但是却比较稳定

```c
#syscall;

probe sys_enter_read{
    arg := args->filename;
    out("%s %s", comm(), arg);
}
```

## 网络

`net_dev_start_xmit` 是 Linux 内核网络子系统的一部分，它是一个内联函数，用于启动网络设备的数据包发送流程。
这个函数通过网络设备操作集（net_device_ops）指定的特定函数来启动给定数据包的发送。

```c
#net;

BEGIN {
    out("%s\n", "Tracing  unusual skb dorp stacks. Hit Ctrl-C to end.");
}

probe net_dev_start_xmit{
    map[comm()] |> coun();
}
```

```c
#skb;

BEGIN {
    out("%s\n", "Tracing  unusual skb dorp stacks. Hit Ctrl-C to end.");
}

probe consume_skb{
    map[comm()] |> count();    
}
```

```c
#skb;

probe kfree_skb {
    skb[comm()] |> count();
}
```



## 安全

使用下面这个系统调用来监控对应的容器
```c
#syscalls;

probe sys_enter_renameat2{
    name := args->oldname;
    out("%s %s\n", comm(), name);
}
```