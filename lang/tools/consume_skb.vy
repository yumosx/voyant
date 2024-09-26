#skb;

BEGIN {
    out("%s\n", "Tracing  unusual skb dorp stacks. Hit Ctrl-C to end.");
}

probe consume_skb{
    map[comm()] |> count();    
}