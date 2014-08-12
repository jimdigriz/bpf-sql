/* get 'line' speed */

struct bpf_insn bpf_insns[] = {
	/* A = C[0] */
	BPF_STMT(BPF_LD+BPF_ABS, 0),

	/* A = C[1] */
	BPF_STMT(BPF_LD+BPF_ABS, 1),

	/* finished */
	BPF_STMT(BPF_RET+BPF_K, 0),
};

struct bpf_program bpf_prog = {
	.bf_len		= sizeof(bpf_insns)/sizeof(struct bpf_insn),
	.bf_insns	= bpf_insns,
};

column_t columns[] = {
		{	/* C[0] */
			.filename	= "sample-data/day16265.tim.bin",
		},
		{	/* C[1] */
			.filename	= "sample-data/day16265.tv2nspid.bin",
		},
};

bpf_sql_t bpf_sql = {
	.nkeys	= 1,
	.width	= 1,

	.prog	= &bpf_prog,

	.ncols	= 2,
	.col	= columns,
};
