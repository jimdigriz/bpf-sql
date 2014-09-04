#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

/* SELECT TIM,TV2NSPID,COUNT(TV2NSPID),SUM(TV2NSPID) */

struct bpf_insn bpf_insns[] = {
	/* R[0] = C[0] */
	BPF_STMT(BPF_LD+BPF_ABS, 0),
	BPF_STMT(BPF_ST+BPF_REC, 0),

	/* R[1] = C[1] */
	BPF_STMT(BPF_LD+BPF_ABS, 1),
	BPF_STMT(BPF_ST+BPF_REC, 1),

	/* automatically finds in G */
	
	/* R[2]++ */
	BPF_STMT(BPF_LD+BPF_REC, 2),
	BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 1),
	BPF_STMT(BPF_ST+BPF_REC, 2),

	/* R[3] += C[1] */
	BPF_STMT(BPF_LD+BPF_ABS, 1),
	BPF_STMT(BPF_MISC+BPF_TAX, 0),
	BPF_STMT(BPF_LD+BPF_REC, 3),
	BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
	BPF_STMT(BPF_ST+BPF_REC, 3),

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
	.nkeys	= 2,
	.width	= 2,

	.prog	= &bpf_prog,

	.ncols	= ARRAY_SIZE(columns),
	.col	= columns,
};
