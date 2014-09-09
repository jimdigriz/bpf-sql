#include <stdint.h>

#include "bpf-sql.h"

/* get 'line' (noop) speed */

static struct bpf_insn bpf_insns[] = {
	/* A = C[0] */
	BPF_STMT(BPF_LD+BPF_ABS, 0),

	/* A = C[1] */
	BPF_STMT(BPF_LD+BPF_ABS, 1),

	/* finished */
	BPF_STMT(BPF_RET+BPF_K, 0),
};

static struct bpf_program bpf_prog = {
	.bf_len		= ARRAY_SIZE(bpf_insns),
	.bf_insns	= bpf_insns,
};

static struct column columns[] = {
	{	/* C[0] */
		.filename	= "sample-data/day16265.tim.bin",
	},
	{	/* C[1] */
		.filename	= "sample-data/day16265.tv2nspid.bin",
	},
};

static struct data_desc desc[] = {
	{
		.t		= TRIE,
		.w		= 1,
	},
	{
		.t		= DATA,
		.w		= 1,
	},
};

struct bpf_sql bpf_sql = {
	.ndesc	= ARRAY_SIZE(desc),
	.desc	= desc,

	.prog	= &bpf_prog,

	.ncols	= ARRAY_SIZE(columns),
	.col	= columns,
};
