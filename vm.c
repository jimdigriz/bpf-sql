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
#include <errno.h>
#include <malloc.h>

#include "data.h"
#include "bpf-sql.h"
#include "engine.h"

#include "program.h"

data_t G;

static void print_cb(const record_t *R)
{
	for (int i = 0; i < bpf_sql.nkeys; i++)
		printf("%" PRId64 "\t", be64toh(R->r[i]));
	for (int i = 0; i < bpf_sql.width; i++)
		printf("%" PRId64 "\t", be64toh(R->d[i]));
	printf("\n");
}

int main(int argc, char **argv, char *env[])
{
	int cfd[bpf_sql.ncols];
	struct stat sb[bpf_sql.ncols];
	int64_t *c[bpf_sql.ncols];

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

#ifndef NDEBUG
	if (!mallopt(M_CHECK_ACTION, 0))
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "mallopt(M_CHECK_ACTION)");
#endif
	if (!mallopt(M_TOP_PAD, 64*1024*1024))
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "mallopt(M_TOP_PAD)");

	data_newrecord(&G, bpf_sql.nkeys, bpf_sql.width);
	G.nR = 0;
	G.c = calloc(1<<CMASK, sizeof(data_t *));
	if (!G.c)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(G.c)");

	for (int r=0; r < nrows; r++, C[0]++, C[1]++) {
		int ret = run(&G, &bpf_sql, C);
		if (ret)
			error_at_line(EX_SOFTWARE, 0, __FILE__, __LINE__, "run(r=%d) != 0", r);
	}

	munmap(c[0], sb[0].st_size);
	munmap(c[1], sb[1].st_size);

	data_iterate(&G, print_cb);

	return(EX_OK);
}
