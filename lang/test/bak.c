int compile_probe_str(node_t* call, ebpf_t* e) {
	size_t raddr, size, addr;

	addr = call->annot.addr;
	size = call->annot.size;
	raddr = sizeof(uintptr_t) * call->integer;

	printf("size: %d addr: %d\n", size, addr);

	ebpf_emit(e, MOV(BPF_REG_1, BPF_REG_10));
	ebpf_emit(e, ALU_IMM(BPF_ADD, BPF_REG_1, addr));
	ebpf_emit(e, MOV_IMM(BPF_REG_2, size));
	ebpf_emit(e, MOV(BPF_REG_3, BPF_REG_9));
	ebpf_emit(e, ALU_IMM(BPF_ADD, BPF_REG_3, 16));
	ebpf_emit(e, CALL(BPF_FUNC_probe_read));
}