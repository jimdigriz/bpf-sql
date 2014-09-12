#include <stdint.h>

#include "bpf-sql.h"

/* SELECT TGVENDOR,FREQ(UNIPFAGT) WHERE TGVENDOR IN (1,2,3,4) */

static struct bpf_insn bpf_insns[] = {
	/* C[0] IN (1,2,3,4) */
	BPF_STMT(BPF_LD+BPF_ABS, 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 1, 0, 4),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 2, 0, 3),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 3, 0, 2),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 4, 0, 1),

	BPF_STMT(BPF_RET+BPF_K, 0),

	/* R[0] = C[0] */
	BPF_STMT(BPF_ST+BPF_REC, 0),

	BPF_STMT(BPF_LD+BPF_ABS, 1),
	BPF_STMT(BPF_ST+BPF_REC, 1),

	/* R <- G */
	BPF_STMT(BPF_MISC+BPF_LDR, 0),

	/* R[2]++ */
	BPF_STMT(BPF_LD+BPF_REC, 2),
	BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 1),
	BPF_STMT(BPF_ST+BPF_REC, 2),

	/* G <- R */
	BPF_STMT(BPF_MISC+BPF_STR, 0),

	/* finished */
	BPF_STMT(BPF_RET+BPF_K, 0),
};

static struct bpf_program bpf_prog = {
	.bf_len		= ARRAY_SIZE(bpf_insns),
	.bf_insns	= bpf_insns,
};

static struct column columns[] = {
	{	/* C[0] */
		.filename	= "sample-data/day16265.tgvendor.bin",
	},
	{	/* C[1] */
		.filename	= "sample-data/day16265.unipfagt.bin",
	},
};

static struct data_desc desc[] = {
	{
		.t		= TRIE,
		.w		= 1,
	},
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
