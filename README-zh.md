# voyant

**voyant 是一个基于 bpf 指令集的动态追踪领域特定语言**，

**它相比于其它的动态追踪编程语言具有下面这些优势**:

1. **轻量+高性能**: 
    - 编译器和解析器均手工打造，未借助如yacc或llvm等外部编译器工具。
    - 这种自主开发的方法带来了显著的优势, 那就是在一些资源受限的环境中可以得到很好的发挥,
    - 文件 `voyant` 的大小是文件 `bpftrace` 的 0.0295560441 倍。

2. **语义一致性**: voyant 旨在与通用编程语言保持高度一致性，这样做大大提高了易用性。用户将发现，使用我们的DSL就像使用熟悉的编程语言一样自然和直观。

3. **内核兼容性**: 我们在设计时特别注意与内核的兼容性。尽管BPF最新特性颇具吸引力，但是这些新的版本并不是被一些旧的内核支持。我们的目的是确保DSL在广泛的内核环境中都能稳定运行，从而满足大多数用户的需求。

## 使用

### 从源码构建

```shell
git clone xxx
cd lang
make
./voyant main.y
```

### 前置检查
```shell
#检查时候有vmlinux
ls -la /sys/kernel/btf/vmlinux
```



### tracepoint

目前我们程序只支持挂载到内核的跟踪程序上, 这是因为选择跟踪点挂载程序更加的稳定

在编写我们的 eBPF 程序之前, 我们可以通过下面这几种方式, 来查看跟踪点类型和跟踪点函数参数的类型
```shell
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/format
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_execve/format
```

首先我们需要在程序中表示出当前跟踪点的类型, syscall表示当前的跟踪点是属于系统调用这个跟踪点下面的
```cpp
#syscall; 
```

然后选择对应的跟踪点:
```cpp
probe sys_enter_execve{

}
```

### kprobe

kprobe是Linux内核提供的另外一种动态跟踪工具，kprobe的好处就是多+动态, 在我们的编程语言中如果你想使用kprobe的话, 首先需呀
```c
#kprobe;
```

然后选择对应的kprobe
```c
probe do_mmap{

}
```


### Hello, World

```c
#syscalls;

probe sys_enter_execve {
    out("%s\n", "hello, world");
}

probe sys_exit_execve{
    out("%s\n", "bye");
}
```
- probe 是一个关键字，其后通常跟随一个指定的跟踪点变量。编译器能够自动推断出该跟踪点的标识符（ID），并将随后的 {} 代码块作为跟踪点的挂载程序。这种设计使得跟踪点的设置和程序的挂载变得简洁而直观。
- 用户态输出函数: out 是一个专为用户态设计的输出信息函数，其语法与 printf 类似，但目前我们仅支持字符串（%s）和整数（%d）两种格式化输出。值得注意的是，out 函数的实现基于 bpf map array 和 perf ring buffer 技术，这种底层实现确保了输出操作的高效性和稳定性。


### 变量

```c
#syscalls;

probe sys_enter_execve {
    a := 1;
    out("%d\n", a);
}
```
- `a := 0` 表示声明一个变量


### 辅助函数

在voyant 我们提供了一下辅助函数, 这些辅助函数的返回值有两种类型, 分别是
- 整数类型，pid、cpu
- 字符串类型, comm

```c
#syscalls;

probe sys_enter_execve {
    out("pid: %d, cpu: %d", pid(), cpu());
}
```

### 跟踪点函数参数

```c
#syscalls;

probe sys_enter_mmap {
    len := args->len;
    fd  := args->fd;

    out("%-14d %-12d\n", pid(), comm(), len, fd);
}
```

跟踪点参数有多种类型, 通常有两种类型:
- 整数类型
- 字符串类型
- 复合类型, 这种类型, 会在后面支持


### BPF hash map

```c
#syscalls;

//示例1
probe sys_enter_execve {
    map[comm()] |> count();
}
```
- **Map的作用域**: 不同于变量需要声明和做相应的寄存器分配，map的所有的数据都是存放在栈上面的

- **Map 键值初始化**: 使用 `map[comm()]` 语句，我们可以创建一个 map，其中键由 `comm()` 函数生成，该函数通常返回当前进程的名称。如果 map 中的某个键尚未被赋值，其对应的值将默认初始化为 0。这种设计简化了对进程特定数据的跟踪和管理。

- **方法调用操作符**: `|>` 是一个特殊的操作符，用于表示方法调用的语义。它的工作方式类似于 Java 中的 `1.add()`，即将数字 1 作为参数传递给 `add()` 方法。这种设计允许我们将操作符用于函数的链式调用，为实现更复杂的数据处理提供了灵活性。

- **支持函数组合**: 我们的设计允许通过 `|>` 操作符实现多个函数的层级调用，从而创建组合函数的效果。例如，在表达式 `map[pid()] |> count(1) |> hist();` 中，我们首先通过 `pid()` 获取进程 ID，然后调用 `count(1)` 对每个进程的计数进行累加，最后通过 `hist()` 函数生成一个统计直方图。

- **计数函数**: `count()` 是一个简洁的函数调用，表示每次调用时将对应的计数器值增加 1。这种设计使得对事件或数据点的计数变得直观和易于实现。

- **用户态的输出:** 在使用map的一系列组合函数的时候, 我们并不需要实时打印其结果, 因为在你结束程序的时候, 我们会在用户态输出 map 的键(key) 和值(value)

### 获取跟踪点函数的参数

```c
#syscalls;

probe sys_enter_execve {
    arg := args->filename;
    out("%s\n", arg);
}
```
目前该功能整体上尚未达到完全稳定，但我可以确认，在捕获sys_enter_execve和sys_enter_open系统调用的filename参数方面，其表现是极为可靠的。


### BEGIN 表达式

```c
BEGIN {
    out("%-18s %-16s %-6s\n", "PID", "COMM", "FILE");
}

probe sys_enter_execve {
    arg := args->filename;
    out("%-18d %-16s %-6s\n", pid(), comm(), arg);
}
```
输出结果:
```c
PID                COMM             FILE  
1428705            barad_agent      /bin/sh
1428706            barad_agent      /bin/sh
1428707            node             /bin/sh
1428708            sh               /usr/bin/which
1428709            node             /bin/sh
1428710            sh               /usr/bin/ps
1428711            node             /bin/sh
1428734            start.sh         /usr/bin/whoami
1428737            start.sh         /usr/bin/grep
1428738            start.sh         /usr/bin/grep
1428739            start.sh         /usr/bin/wc
1428736            start.sh         /usr/bin/ps
```
BEGIN是一个特殊的探针类型，它仅在脚本开始执行时触发一次。此处，我们利用BEGIN探针来定义一个立即执行的代码块，该代码块负责输出格式化的表头，包括进程ID（PID）、命令名称（COMM）和文件路径（FILE）。

### if语句

```c
#syscalls;

probe sys_enter_mmap {
    len := args->len;

    if (len > 0) {
        out("%s\n", comm());
    }
}
```