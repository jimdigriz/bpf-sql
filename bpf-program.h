struct bpf_insn bpf_insns[] = {
	{
		.code	= BPF_RET+BPF_K,
		.jt	= 0,
		.jf	= 0,
		.k	= 2,
	}
};

struct bpf_program bpf_prog = {
	.bf_len		= sizeof(bpf_insns)/sizeof(struct bpf_insn),
	.bf_insns	= bpf_insns,
};
