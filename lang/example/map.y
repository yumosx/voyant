BEGIN{
    states[1] := "ESTABLISHED";
    states[2] := "SYN_SENT";
    states[3] := "SYN_RECV";
    states[4] := "FIN_WAIT1";
    states[5] := "FIN_WAIT2";
    states[6] := "TIME_WAIT";
    states[7] := "CLOSE";
    states[8] = "CLOSE_WAIT";
    states[9] = "LAST_ACK";
    states[10] = "LISTEN";
    states[11] = "CLOSING";
    states[12] = "NEW_SYN_RECV";
}


END {
    close(tcp_states);
}