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
#include "bpf.h"

struct bpf_insn bpf_insns[] = {
	{
		.code	= BPF_RET+BPF_K,
		.jt	= 0,
		.jf	= 0,
		.k	= -1,
	}
};

struct bpf_program bpf_prog = {
	.bf_len		= sizeof(bpf_insns)/sizeof(struct bpf_insn),
	.bf_insns	= bpf_insns,
};

int run(const struct bpf_program *prog, const int columns, const int64_t *p, int64_t *m)
{
	int64_t a = 0, x = 0;
	int cycles, pc = 0;

	for (cycles = 0; cycles < 10 && pc < bpf_prog.bf_len; cycles++) {
		struct bpf_insn *insn = &bpf_insns[pc];

		switch (insn->code) {
		case BPF_RET:
			m[0] = p[0];
			m[1] = p[1];
			return insn->k;
		default:
			printf("moo default\n");
			break;
		}

		pc++;
	}

	return 0;
}


int main(int argc, char **argv)
{
	int cfd[2];
	struct stat sb[2];
	int64_t *c[2];
	int r, nrows;

	cfd[0] = open("day16265.tim.bin", O_RDONLY);
	fstat(cfd[0], &sb[0]);

	cfd[1] = open("day16265.tv2nspid.bin", O_RDONLY);
	fstat(cfd[1], &sb[1]);

	assert(sb[0].st_size == sb[1].st_size);

	nrows = sb[0].st_size/sizeof(int64_t);

	c[0] = mmap(NULL, sb[0].st_size, PROT_READ, MAP_SHARED, cfd[0], 0);
	close(cfd[0]);

	c[1] = mmap(NULL, sb[1].st_size, PROT_READ, MAP_SHARED, cfd[1], 0);
	close(cfd[1]);

	for (r=0; r<nrows; r++) {
		int64_t p[2] = {0};
		int64_t m[2] = {0};

		p[0] = be64toh(c[0][r]);
		p[1] = be64toh(c[1][r]);

		if (run(&bpf_prog, 2, p, m)) {
			printf("%" PRId64 "\t%" PRId64 "\n", m[0], m[1]);
		}
	}

	munmap(c[0], sb[0].st_size);
	munmap(c[1], sb[1].st_size);

	return(EX_OK);
}
