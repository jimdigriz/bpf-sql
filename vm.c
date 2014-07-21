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

#include "bpf.h"
#include "bpf-program.h"

#define HACK_SIZE 2

typedef struct {
	int64_t r[HACK_SIZE];
} record_key_t;

typedef struct {
	record_key_t	key;

	int64_t		r[HACK_SIZE];
	
	UT_hash_handle	hh;
} record_t;

int run(const struct bpf_program *prog, record_t **records, const int64_t *C[HACK_SIZE])
{
	struct bpf_insn *pc = &prog->bf_insns[0];
	int64_t A = 0;
	int64_t X = 0;
	int64_t M[BPF_MEMWORDS] = {0};
	record_t *R = NULL;
	int ret;
	
	--pc;
	while (1) {
		int64_t v;
		++pc;

		switch (BPF_CLASS(pc->code)) {
		case BPF_LD:
			assert(BPF_SIZE(pc->code) == 0x00);

			switch (BPF_MODE(pc->code)) {
			case BPF_ABS:
				assert(pc->k < HACK_SIZE);
				A = *C[pc->k];
				break;
			case BPF_IND:
				assert(X + pc->k < HACK_SIZE);
				A = *C[X + pc->k];
				break;
			case BPF_IMM:
				A = pc->k;
				break;
			case BPF_MEM:
				assert(pc->k < BPF_MEMWORDS);
				A = M[pc->k];
				break;
			case BPF_REC:
				assert(R);
				assert(pc->k < HACK_SIZE);
				A = R->key.r[pc->k];
				break;
			default:
				error_at_line(EX_DATAERR, 0, __FILE__, __LINE__, "LD: UNKNOWN MODE");
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
			case BPF_REC:
				assert(R);
				assert(pc->k < HACK_SIZE);
				X = R->key.r[pc->k];
				break;
			default:
				error_at_line(EX_DATAERR, 0, __FILE__, __LINE__, "LDX: UNKNOWN MODE");
			}
			break;
		case BPF_ST:
			switch (BPF_MODE(pc->code)) {
			case BPF_MEM:
				assert(pc->k < BPF_MEMWORDS);
				M[pc->k] = A;
				break;
			case BPF_REC:
				assert(pc->k < HACK_SIZE);
				if (!R) {
					R = malloc(sizeof(record_t));
					memset(R, 0, sizeof(record_t));
				}
				R->key.r[pc->k] = A;
				break;
			default:
				error_at_line(EX_DATAERR, 0, __FILE__, __LINE__, "ST: UNKNOWN MODE");
			}
			break;
		case BPF_STX:
			switch (BPF_MODE(pc->code)) {
			case BPF_MEM:
				assert(pc->k < BPF_MEMWORDS);
				M[pc->k] = X;
				break;
			case BPF_REC:
				assert(pc->k < HACK_SIZE);
				if (!R) {
					R = malloc(sizeof(record_t));
					memset(R, 0, sizeof(record_t));
				}
				R->key.r[pc->k] = X;
				break;
			default:
				error_at_line(EX_DATAERR, 0, __FILE__, __LINE__, "STX: UNKNOWN MODE");
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
				error_at_line(EX_DATAERR, 0, __FILE__, __LINE__, "ALU: UNKNOWN OP");
			}
			break;
		case BPF_JMP:
			switch (BPF_SRC(pc->code)) {
			case BPF_X:
				v = X;
				break;
			default: /* BPF_K */
				v = pc->k;
				break;
			}

			switch (BPF_OP(pc->code)) {
			case BPF_JA:
				pc += v;
				continue;
			case BPF_JGT:
				pc += (A > v) ? pc->jt : pc->jf;
				continue;
			case BPF_JGE:
				pc += (A >= v) ? pc->jt : pc->jf;
				continue;
			case BPF_JEQ:
				pc += (A == v) ? pc->jt : pc->jf;
				continue;
			case BPF_JSET:
				pc += (A & v) ? pc->jt : pc->jf;
				continue;
			default:
				error_at_line(EX_DATAERR, 0, __FILE__, __LINE__, "JMP: UNKNOWN OP");
			}
			break;
		case BPF_RET:
			switch (BPF_RVAL(pc->code)) {
			case BPF_K:
				ret = pc->k;
				break;
			case BPF_X:
				ret = X;
				break;
			case BPF_A:
				ret = A;
				break;
			default:
				error_at_line(EX_DATAERR, 0, __FILE__, __LINE__, "RET: UNKNOWN RVAL");
			}

			if (!ret) {
				assert(!R);
				return 0;
			}

			assert(R);

			//R->key.r[0]	= *C[0];
			//R->key.r[1]	= *C[1];
			//R->r[0]	= 1;
			//R->r[1]	= 2;

			HASH_ADD(hh, *records, key, sizeof(record_key_t), R);

			R = NULL;

			return ret;
			break;
		case BPF_MISC:
			switch (BPF_MISCOP(pc->code)) {
			case BPF_TAX:
				X = A;
				break;
			case BPF_TXA:
				A = X;
				break;
			}
			break;
		default:
			error_at_line(EX_UNAVAILABLE, 0, __FILE__, __LINE__, "UNKNOWN CLASS");
		}
	}

	return 0;
}

int main(int argc, char **argv, char *env[])
{
	int cfd[HACK_SIZE];
	struct stat sb[HACK_SIZE];
	int64_t *c[HACK_SIZE];
	record_t *records = NULL;
	int nrows;

	cfd[0] = open("day16265.tim.bin", O_RDONLY);
	fstat(cfd[0], &sb[0]);

	cfd[1] = open("day16265.tv2nspid.bin", O_RDONLY);
	fstat(cfd[1], &sb[1]);

	assert(sb[0].st_size == sb[1].st_size);

	c[0] = mmap(NULL, sb[0].st_size, PROT_READ, MAP_SHARED, cfd[0], 0);
	close(cfd[0]);

	c[1] = mmap(NULL, sb[1].st_size, PROT_READ, MAP_SHARED, cfd[1], 0);
	close(cfd[1]);

	nrows = sb[0].st_size/sizeof(int64_t);

	const int64_t *C[HACK_SIZE] = { c[0], c[1] };
	for (int r=0; r<nrows; r++, C[0]++, C[1]++)
		assert(run(&bpf_prog, &records, C) > -1);

	munmap(c[0], sb[0].st_size);
	munmap(c[1], sb[1].st_size);

//	for(r=records; r != NULL; r=r->hh.next)
//		printf("%" PRId64 "\t%" PRId64 "\n", be64toh(r->key.tim), be64toh(r->key.tv2nspid));

	return(EX_OK);
}
