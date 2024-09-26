#net;

probe net_dev_start_xmit{
    map[comm()] |> coun();
} 