#power;

BEGIN {
    printf("%s\n", "Sampling CPU freq system-wide & by process. Ctrl-C to end.");
}

probe cpu_frequency{
    curfreq[cpu()] |> count();
}