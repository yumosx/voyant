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
    printf("%d", a);
}
```


### bpf map

```y
probe sys_enter_execve {
    map[pid()] = 2;
    out("%d", map[pid()]);
}
```


### pred expression

I use the lower version linux kernal, this program crash, because the bpf insns limit

```y
probe sys_enter_execve /comm() == "bash"/ {
    out("%s", comm());
}
```
