   0: (bf) r9 = r1
   1: (b7) r0 = 0
   2: (7b) *(u64 *)(r10 -96) = r0
   3: (62) *(u32 *)(r10 -88) = 0
   4: (62) *(u32 *)(r10 -84) = 0
   5: (62) *(u32 *)(r10 -80) = 0
   6: (62) *(u32 *)(r10 -76) = 0
   7: (bf) r1 = r10
   8: (07) r1 += -88
   9: (b7) r2 = 16
  10: (85) call bpf_get_current_comm#165040
  11: (bf) r1 = r10
  12: (07) r1 += -72
  13: (b7) r2 = 64
  14: (bf) r3 = r9
  15: (07) r3 += 16
  16: (85) call bpf_probe_read_user_str#-68816
  17: (b7) r0 = 1
  18: (7b) *(u64 *)(r10 -8) = r0
  19: (85) call bpf_get_smp_processor_id#164032
  20: (bf) r3 = r0
  21: (bf) r1 = r9
  22: (18) r2 = map[id:169]
  24: (bf) r4 = r10
  25: (07) r4 += -96
  26: (b7) r5 = 96
  27: (85) call bpf_perf_event_output_tp#-67408
  28: (b7) r0 = 0
  29: (95) exit