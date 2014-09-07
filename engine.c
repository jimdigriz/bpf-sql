#include <stdint.h>
#include <assert.h>
#include <endian.h>
#include <sysexits.h>

#include "bpf-sql.h"
#include "data.h"

int run(const struct bpf_sql *bpf_sql, struct data *G, const int64_t **C)
{
	struct bpf_insn *pc = &bpf_sql->prog->bf_insns[0];
	int64_t A = 0;
	int64_t X = 0;
	int64_t M[BPF_MEMWORDS] = {0};
	int64_t *R = G->R;

	pc--;
	while (1) {
		int64_t v;

		pc++;

		switch (BPF_CLASS(pc->code)) {
		case BPF_LD:
			assert(BPF_SIZE(pc->code) == 0x00);

			switch (BPF_MODE(pc->code)) {
			case BPF_ABS:
				assert(pc->k < bpf_sql->ncols);
				A = be64toh(*C[pc->k]);
				break;
			case BPF_IND:
				assert(X + pc->k < bpf_sql->ncols);
				A = be64toh(*C[X + pc->k]);
				break;
			case BPF_IMM:
				A = pc->k;
				break;
			case BPF_MEM:
				assert(pc->k < BPF_MEMWORDS);
				A = M[pc->k];
				break;
			case BPF_REC:
				assert(pc->k < G->width);
				A = be64toh(R[pc->k]);
				break;
			default:
				ERROR0(EX_SOFTWARE, "LD: UNKNOWN MODE");
			}
			break;
		case BPF_LDX:
			assert(BPF_SIZE(pc->code) == 0x00);

			switch (BPF_MODE(pc->code)) {
			case BPF_IMM:
				X = pc->k;
				break;
			case BPF_MEM:
				assert(pc->k < BPF_MEMWORDS);
				X = M[pc->k];
				break;
			default:
				ERROR0(EX_SOFTWARE, "LDX: UNKNOWN MODE");
			}
			break;
		case BPF_ST:
			switch (BPF_MODE(pc->code)) {
			case BPF_MEM:
				assert(pc->k < BPF_MEMWORDS);
				M[pc->k] = A;
				break;
			case BPF_REC:
				assert(pc->k < G->width);
				R[pc->k] = htobe64(A);
				break;
			default:
				ERROR0(EX_SOFTWARE, "ST: UNKNOWN MODE");
			}
			break;
		case BPF_STX:
			switch (BPF_MODE(pc->code)) {
			case BPF_MEM:
				assert(pc->k < BPF_MEMWORDS);
				M[pc->k] = X;
				break;
			default:
				ERROR0(EX_SOFTWARE, "STX: UNKNOWN MODE");
			}
			break;
		case BPF_ALU:
			switch (BPF_SRC(pc->code)) {
			case BPF_K:
				v = pc->k;
				break;
			case BPF_X:
				v = X;
				break;
			default:
				ERROR0(EX_SOFTWARE, "ALU: UNKNOWN SRC");
			}

			switch (BPF_OP(pc->code)) {
			case BPF_ADD:
				A += v;
				break;
			case BPF_SUB:
				A -= v;
				break;
			case BPF_MUL:
				A *= v;
				break;
			case BPF_DIV:
				A /= v;
				break;
			case BPF_AND:
				A &= v;
				break;
			case BPF_OR:
				A |= v;
				break;
			case BPF_LSH:
				A <<= v;
				break;
			case BPF_RSH:
				A >>= v;
				break;
			case BPF_NEG:
				A = -A;
				break;
			default:
				ERROR0(EX_SOFTWARE, "ALU: UNKNOWN OP");
			}
			break;
		case BPF_JMP:
			switch (BPF_SRC(pc->code)) {
			case BPF_K:
				v = pc->k;
				break;
			case BPF_X:
				v = X;
				break;
			default:
				ERROR0(EX_SOFTWARE, "JMP: UNKNOWN SRC");
			}

			switch (BPF_OP(pc->code)) {
			case BPF_JA:
				pc += v;
				break;
			case BPF_JGT:
				pc += (A > v) ? pc->jt : pc->jf;
				break;
			case BPF_JGE:
				pc += (A >= v) ? pc->jt : pc->jf;
				break;
			case BPF_JEQ:
				pc += (A == v) ? pc->jt : pc->jf;
				break;
			case BPF_JSET:
				pc += (A & v) ? pc->jt : pc->jf;
				break;
			default:
				ERROR0(EX_SOFTWARE, "JMP: UNKNOWN OP");
			}
			break;
		case BPF_RET:
			switch (BPF_RVAL(pc->code)) {
			case BPF_K:
				v = pc->k;
				break;
			case BPF_X:
				v = X;
				break;
			case BPF_A:
				v = A;
				break;
			default:
				ERROR0(EX_SOFTWARE, "RET: UNKNOWN RVAL");
			}

			return v;
		case BPF_MISC:
			switch (BPF_MISCOP(pc->code)) {
			case BPF_TAX:
				X = A;
				break;
			case BPF_TXA:
				A = X;
				break;
			case BPF_LDR:
				data_load(G);
				break;
			case BPF_STR:
				data_store(G);
				break;
			default:
				ERROR0(EX_SOFTWARE, "MISC: UNKNOWN MISCOP");
			}
			break;
		default:
			ERROR0(EX_SOFTWARE, "UNKNOWN CLASS");
		}
	}
}
