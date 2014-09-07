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
#include <errno.h>
#include <malloc.h>

#include "bpf-sql.h"
#include "program.h"
#include "data.h"
#include "engine.h"

datag_t *G;

static void print_cb(const record_t *R)
{
	for (int i = 0; i < bpf_sql.nkeys; i++)
		printf("%" PRId64 "\t", be64toh(R->k[i]));
	for (int i = 0; i < bpf_sql.width; i++)
		printf("%" PRId64 "\t", be64toh(R->d[i]));
	printf("\n");
}

int main(int argc, char **argv, char *env[])
{
	const int64_t *C[bpf_sql.ncols];

	assert(bpf_sql.ncols > 0);

	for (int i = 0; i < bpf_sql.ncols; i++) {
		bpf_sql.col[i].fd = open(bpf_sql.col[i].filename, O_RDONLY);
		if (bpf_sql.col[i].fd == -1)
			ERRORV(EX_OSERR, "open('%s')", bpf_sql.col[i].filename);

		fstat(bpf_sql.col[i].fd, &bpf_sql.col[i].sb);

		assert(i == 0 || bpf_sql.col[0].sb.st_size == bpf_sql.col[i].sb.st_size);

		bpf_sql.col[i].m = mmap(NULL, bpf_sql.col[i].sb.st_size, PROT_READ, MAP_SHARED, bpf_sql.col[i].fd, 0);
		if (bpf_sql.col[i].m == MAP_FAILED)
			ERRORV(EX_OSERR, "mmap('%s')", bpf_sql.col[i].filename);

		close(bpf_sql.col[i].fd);

		C[i] = bpf_sql.col[i].m;
	}

	int nrows = bpf_sql.col[0].sb.st_size/sizeof(int64_t);

#ifndef NDEBUG
	if (!mallopt(M_CHECK_ACTION, 0))
		ERROR0(EX_OSERR, "mallopt(M_CHECK_ACTION)");
#endif
	if (!mallopt(M_TOP_PAD, 64*1024*1024))
		ERROR0(EX_OSERR, "mallopt(M_TOP_PAD)");

	data_init(&G, bpf_sql.nkeys, bpf_sql.width);

	for (int r=0; r < nrows; r++, C[0]++, C[1]++) {
		int ret = run(G, &bpf_sql, C);
		if (ret)
			ERRORV(EX_SOFTWARE, "run(r=%d) != 0", r);
	}

	for (int i = 0; i < bpf_sql.ncols; i++)
		if (munmap(bpf_sql.col[i].m, bpf_sql.col[i].sb.st_size) == -1)
			ERRORV(EX_OSERR, "munmap('%s')", bpf_sql.col[i].filename);

	data_iterate(G, print_cb);

	return(EX_OK);
}
