# voyant

> NOTE: There are still a lot of bugs in this project, such as memory usage in some place is not will released

voyant is domain specific language based on the eBPF instruction set (insn) and system calls;

ulike other eBPF tools, it is designed to be lightweight and easy extendable

There are three aspectes that can account for my option;
1. First of all, no LLVM, indeed LLVM is an exceptional tool for building complier backends, but LLVM is counted in ten millions， the light weight is one of my goals and the rules out LLVM.

2. The second, our dsl will offer the similarly level of expressivity as general-purpose programming language, also extending the semantics in certain aspectes;


## how to install

```c
cd lang
make
sudo ./voyant main.y
```

## syntax

## hello, world

```y
probe sys_enter_execve {
    out("%s", "Hello, World!");
}
```

### variable

```y
probe sys_enter_execve {
    a = pid();
    out("%d", a);
}
```

### helper function

```y
probe sys_enter_execve {
    out("%s\n", com(), pid(), cpu());    
}
```

### bpf map

```y
probe sys_enter_execve {
    map[pid()] |> count();
    out("%d", map[pid()]);
}

probe sys_enter_execve {
    map[cpu()] |> count();
}
```

### begin
```c
BEGIN {
    out("%-18s %-16s %-6s\n", "PID", "COMM", "FILE");
}

probe sys_enter_open {
    out("%-18d %-16s %-6s\n", pid(), comm(), arg());
}
```