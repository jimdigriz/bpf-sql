#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

/* get 'line' (noop) speed */

struct bpf_insn bpf_insns[] = {
	/* A = C[0] */
	BPF_STMT(BPF_LD+BPF_ABS, 0),

	/* A = C[1] */
	BPF_STMT(BPF_LD+BPF_ABS, 1),

	/* finished */
	BPF_STMT(BPF_RET+BPF_K, 0),
};

struct bpf_program bpf_prog = {
	.bf_len		= ARRAY_SIZE(bpf_insns),
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

	.ncols	= ARRAY_SIZE(columns),
	.col	= columns,
};
