probe sys:execute 
{  
    print("%d", pid());
}

probe sys:execute
{
    execute[pid(), comm()]++;
    printf(execute[pid()]);
}

probe sys:execute 
{
    a = pid();
    if (a == 2) {
        print("%s", "pid is 2");
    } else {
        print("%s", "pid is other");
    }
}

probe sys:execute /pid() == 1/
{
    print(comm());
}
