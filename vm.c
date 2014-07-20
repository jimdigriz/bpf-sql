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
#include "bpf.h"

#include "bpf-program.h"

#define MAX_CYCLES_PER_RECORD	10

typedef struct {
	int64_t	tim;
	int64_t	count;
	
	UT_hash_handle hh;
} results_key_t;

typedef struct {
	int	sum;
	int	count;
	
	UT_hash_handle hh;
} results_value_t;

int run(const struct bpf_program *prog, results_t *results, const int64_t *C[2])
{
	int64_t A = 0;
	int64_t X = 0;
	int pc = 0;
	int cycles = 0;
	
	for (; cycles < MAX_CYCLES_PER_RECORD && pc < bpf_prog.bf_len; cycles++) {
		struct bpf_insn *insn = &bpf_insns[pc];

		switch (BPF_CLASS(insn->code)) {
		case BPF_RET:
			switch (BPF_RVAL(insn->code)) {
			case BPF_K:
				printf("%" PRId64 "\t%" PRId64 "\n", be64toh(*C[0]), be64toh(*C[1]));
				return insn->k;
			case BPF_X:
				return X;
			case BPF_A:
				return A;
			}

			error_at_line(EX_DATAERR, 0, __FILE__, __LINE__, "UNKNOWN RVAL");
		default:
			error_at_line(EX_UNAVAILABLE, 0, __FILE__, __LINE__, "UNKNOWN CLASS");
		}

		pc++;
	}

	return 0;
}


int main(int argc, char **argv, char *env[])
{
	int cfd[2];
	struct stat sb[2];
	int64_t *c[2];
	results_t *results = NULL;
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

	const int64_t *C[2] = { c[0], c[1] };
	for (int r=0; r<nrows; r++, C[0]++, C[1]++) {
		assert(run(&bpf_prog, results, C) > -1);
	}

	munmap(c[0], sb[0].st_size);
	munmap(c[1], sb[1].st_size);

	return(EX_OK);
}
