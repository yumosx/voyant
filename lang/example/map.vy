BEGIN{
    states[1] := "ESTABLISHED";
    states[2] = "SYN_SENT";
    states[3] = "SYN_RECV";
    states[4] = "FIN_WAIT1";
    states[5] = "FIN_WAIT2";
    states[6] = "TIME_WAIT";
    states[7] = "CLOSE";
    states[8] = "CLOSE_WAIT";
}