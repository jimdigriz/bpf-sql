#include <stdint.h>

#include "bpf-sql.h"

/* SELECT HOUR,COUNT(TV2NSPID),SUM(TV2NSPID) WHERE 36000 < TV2NSPID < 36100 OR 36650 < TV2NSPID < 36700 */

static struct bpf_insn bpf_insns[] = {
	/* 36000 < C[1] < 36100 || 36650 < C[1] < 36700 */
	BPF_STMT(BPF_LD+BPF_ABS, 1),
	BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 36000, 0, 1),
	BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 36100, 0, 3),
	BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 36650, 0, 1),
	BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, 36700, 0, 1),

	BPF_STMT(BPF_RET+BPF_K, 0),

	/* R[0] = C[0] - C[0] % 3600 */
	BPF_STMT(BPF_LD+BPF_ABS, 0),
	BPF_STMT(BPF_ALU+BPF_DIV+BPF_K, 3600),
	BPF_STMT(BPF_ALU+BPF_MUL+BPF_K, 3600),
	BPF_STMT(BPF_MISC+BPF_TAX, 0),
	BPF_STMT(BPF_LD+BPF_ABS, 0),
	BPF_STMT(BPF_ALU+BPF_SUB+BPF_X, 0),
	BPF_STMT(BPF_MISC+BPF_TAX, 0),
	BPF_STMT(BPF_LD+BPF_ABS, 0),
	BPF_STMT(BPF_ALU+BPF_SUB+BPF_X, 0),
	BPF_STMT(BPF_ST+BPF_REC, 0),

	/* R <- G */
	BPF_STMT(BPF_MISC+BPF_LDR, 0),

	/* R[1]++ */
	BPF_STMT(BPF_LD+BPF_REC, 1),
	BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, 1),
	BPF_STMT(BPF_ST+BPF_REC, 1),

	/* R[2] += C[1] */
	BPF_STMT(BPF_LD+BPF_ABS, 1),
	BPF_STMT(BPF_MISC+BPF_TAX, 0),
	BPF_STMT(BPF_LD+BPF_REC, 2),
	BPF_STMT(BPF_ALU+BPF_ADD+BPF_X, 0),
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
		.w		= 2,
	},
};

struct bpf_sql bpf_sql = {
	.ndesc	= ARRAY_SIZE(desc),
	.desc	= desc,

	.prog	= &bpf_prog,

	.ncols	= ARRAY_SIZE(columns),
	.col	= columns,
};
