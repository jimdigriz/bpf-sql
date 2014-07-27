#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
#include <endian.h>
#include <sysexits.h>
#include <error.h>
#include <uthash.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "bpf-sql.h"

#include "program.h"

typedef struct {
	int64_t r[HACK_KSIZE];
} record_key_t;

typedef struct {
	record_key_t	key;

	int64_t		r[HACK_RSIZE];
	
	UT_hash_handle	hh;
} record_t;

int run(const bpf_sql_t *bpf_sql, record_t **G, const int64_t **C, record_t **R)
{
	struct bpf_insn *pc = &bpf_sql->prog->bf_insns[0];
	int64_t A = 0;
	int64_t X = 0;
	int64_t M[BPF_MEMWORDS] = {0};
	record_t *R_old;
	
	--pc;
	while (1) {
		int64_t v;
		++pc;

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
				assert(*R);
				assert(pc->k < bpf_sql->nkeys + bpf_sql->width);
				A = (pc->k < bpf_sql->nkeys)
					? be64toh((*R)->key.r[pc->k])
					: be64toh((*R)->r[pc->k - bpf_sql->nkeys]);
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
				if (!*R) {
					*R = malloc(sizeof(record_t));
					if (!*R)
						error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "malloc(R)");
					memset(*R, 0, sizeof(record_t));
				}
				if (pc->k < bpf_sql->nkeys)
					(*R)->key.r[pc->k] = htobe64(A);
				else
					(*R)->r[pc->k - bpf_sql->nkeys] = htobe64(A);
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
			case BPF_X:
				v = X;
				break;
			default: /* BPF_K */
				v = pc->k;
				break;
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
			case BPF_LDR:
				assert(*R);
				HASH_FIND(hh, *G, &(*R)->key, sizeof(record_key_t), R_old);
				if (R_old) {
					HASH_DELETE(hh, *G, R_old);
					free(*R);
					*R = R_old;
				}
			}
			break;
		default:
			error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "UNKNOWN CLASS");
		}
	}

	assert(!*R);
	return 0;
}

int main(int argc, char **argv, char *env[])
{
	int cfd[bpf_sql.ncols];
	struct stat sb[bpf_sql.ncols];
	int64_t *c[bpf_sql.ncols];
	record_t *G = NULL;

	assert(bpf_sql.type == HASH);

	cfd[0] = open(bpf_sql.col[0], O_RDONLY);
	fstat(cfd[0], &sb[0]);

	cfd[1] = open(bpf_sql.col[1], O_RDONLY);
	fstat(cfd[1], &sb[1]);

	assert(sb[0].st_size == sb[1].st_size);

	c[0] = mmap(NULL, sb[0].st_size, PROT_READ, MAP_SHARED, cfd[0], 0);
	close(cfd[0]);

	c[1] = mmap(NULL, sb[1].st_size, PROT_READ, MAP_SHARED, cfd[1], 0);
	close(cfd[1]);

	int nrows = sb[0].st_size/sizeof(int64_t);

	const int64_t *C[HACK_CSIZE] = { c[0], c[1] };
	for (int r=0; r<nrows; r++, C[0]++, C[1]++) {
		record_t *R = NULL;
		record_t *R_old;
		int ret;

		ret = run(&bpf_sql, &G, C, &R);
		if (ret < 0)
			error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "ret < 0");

		if (!ret) {
			assert(!R);
			continue;
		}

		assert(R);
		assert(ret == bpf_sql.nkeys + bpf_sql.width);

		HASH_FIND(hh, G, &R->key, sizeof(record_key_t), R_old);
		if (R_old) {
			HASH_DELETE(hh, G, R_old);
			free(R_old);
		}
		HASH_ADD(hh, G, key, sizeof(record_key_t), R);
	}

	munmap(c[0], sb[0].st_size);
	munmap(c[1], sb[1].st_size);

	for(record_t *R = G; R != NULL; R = R->hh.next) {
		for (int i = 0; i < bpf_sql.nkeys; i++)
			printf("%" PRId64 "\t", be64toh(R->key.r[i]));
		for (int i = 0; i < bpf_sql.width; i++)
			printf("%" PRId64 "\t", be64toh(R->r[i]));
		printf("\n");
	}

	return(EX_OK);
}
