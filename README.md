# voyant

> NOTE: There are still a lot of bugs in this project, such as memory usage in some place is not will released, and about the tracepoint is a hacking

voyant is domain specific language based on the eBPF instruction set (insn) and system calls;

ulike other eBPF tools, it is designed to be lightweight and easy extendable

There are three aspectes that can account for my option;
1. First of all, no LLVM, indeed LLVM is an exceptional tool for building complier backends, but LLVM is counted in ten millions， the light weight is one of my goals and the rules out LLVM.
2. The second, our dsl will offer the similarly level of expressivity as general-purpose programming language, also extending the semantics in certain aspectes;


## syntax

## hello, world

```y
probe sys:execute:enter {
    print("Hello, World!");
}
```

### variable

```y
probe sys:execute:enter {
    a = pid();
    print("%d", a);
}
```
