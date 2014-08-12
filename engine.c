#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <endian.h>
#include <sysexits.h>
#include <error.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>

#include "bpf-sql.h"
#include "data.h"

int run(data_t *G, const bpf_sql_t *bpf_sql, const int64_t **C)
{
	struct bpf_insn *pc = &bpf_sql->prog->bf_insns[0];
	int64_t A = 0;
	int64_t X = 0;
	int64_t M[BPF_MEMWORDS] = {0};
	record_t *R = &G->R[0];
	int Rloaded = 0;

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
				assert(pc->k < bpf_sql->nkeys + bpf_sql->width);
				if (pc->k < bpf_sql->nkeys) {
					A = be64toh(R->r[pc->k]);
				} else {
					if (!Rloaded) {
						R = data_fetch(G, R->r, bpf_sql->nkeys, bpf_sql->width);
						Rloaded = 1;
					}
					A = be64toh(R->d[pc->k - bpf_sql->nkeys]);
				}
				break;
			default:
				error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "LD: UNKNOWN MODE");
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
				error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "LDX: UNKNOWN MODE");
			}
			break;
		case BPF_ST:
			switch (BPF_MODE(pc->code)) {
			case BPF_MEM:
				assert(pc->k < BPF_MEMWORDS);
				M[pc->k] = A;
				break;
			case BPF_REC:
				assert(pc->k < bpf_sql->nkeys + bpf_sql->width);
				if (pc->k < bpf_sql->nkeys) {
					if (Rloaded) {
						memcpy(G->R[0].r, R->r, bpf_sql->nkeys*sizeof(int64_t));
						memcpy(G->R[0].d, R->d, bpf_sql->width*sizeof(int64_t));
						R = &G->R[0];
						Rloaded = 0;
					}
					R->r[pc->k] = htobe64(A);
				} else {
					if (!Rloaded) {
						R = data_fetch(G, R->r, bpf_sql->nkeys, bpf_sql->width);
						Rloaded = 1;
					}
					R->d[pc->k - bpf_sql->nkeys] = htobe64(A);
				}
				break;
			default:
				error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "ST: UNKNOWN MODE");
			}
			break;
		case BPF_STX:
			switch (BPF_MODE(pc->code)) {
			case BPF_MEM:
				assert(pc->k < BPF_MEMWORDS);
				M[pc->k] = X;
				break;
			default:
				error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "STX: UNKNOWN MODE");
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
				error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "ALU: UNKNOWN SRC");
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
				error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "ALU: UNKNOWN OP");
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
				error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "JMP: UNKNOWN SRC");
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
				error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "JMP: UNKNOWN OP");
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
				error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "RET: UNKNOWN RVAL");
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
			default:
				error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "MISC: UNKNOWN MISCOP");
			}
			break;
		default:
			error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "UNKNOWN CLASS");
		}
	}
}
