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

#define HACK_CSIZE 2 /* bpf_sql.ncols */

bpf_sql_t bpf_sql = {
	.ncols	= 2,
	.col	= {
			"sample-data/day16265.tim.bin",
			"sample-data/day16265.tv2nspid.bin"
	},

	.nkeys	= 1,
	.width	= 1,

	.prog	= &bpf_prog,
};