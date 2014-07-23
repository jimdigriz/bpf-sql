struct bpf_insn bpf_insns[] = {
	/* load C[0] into R[0] */
	BPF_STMT(BPF_LD+BPF_ABS, 0),
	BPF_STMT(BPF_ST+BPF_REC, 0),

	/* load C[1] into R[1] */
	BPF_STMT(BPF_LD+BPF_ABS, 1),
	BPF_STMT(BPF_ST+BPF_REC, 1),

	/* fetch from G */
	BPF_STMT(BPF_MISC+BPF_LDR, 0),
	
	/* load R[2] into A, incremental and put back */
	BPF_STMT(BPF_LD+BPF_REC, 2),
	BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 1),
	BPF_STMT(BPF_ST+BPF_REC, 2),

	/* load R[3] into A, incremental by R[1] and put back */
	BPF_STMT(BPF_LD+BPF_REC, 3),
	BPF_STMT(BPF_LDX+BPF_REC, 1),
	BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
	BPF_STMT(BPF_ST+BPF_REC, 3),

	/* R[] into G */
	BPF_STMT(BPF_RET+BPF_K, 4),
};

struct bpf_program bpf_prog = {
	.bf_len		= sizeof(bpf_insns)/sizeof(struct bpf_insn),
	.bf_insns	= bpf_insns,
};
