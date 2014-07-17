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

int main(int argc, char **argv)
{
	int cfd[2];
	struct stat sb[2];
	int64_t *c[2];
	int i;

	cfd[0] = open("day16265.tim.bin", O_RDONLY);
	fstat(cfd[0], &sb[0]);

	cfd[1] = open("day16265.tv2nspid.bin", O_RDONLY);
	fstat(cfd[1], &sb[1]);

	assert(sb[0].st_size == sb[1].st_size);

	c[0] = mmap(NULL, sb[0].st_size, PROT_READ, MAP_SHARED, cfd[0], 0);
	close(cfd[0]);

	c[1] = mmap(NULL, sb[1].st_size, PROT_READ, MAP_SHARED, cfd[1], 0);
	close(cfd[1]);

	for (i=0; i<sb[0].st_size/sizeof(long long int); i++) {
		int64_t nc[2];

		nc[0] = be64toh(c[0][i]);
		nc[1] = be64toh(c[1][i]);

		printf("%" PRId64 "\t%" PRId64 "\n", nc[0], nc[1]);
	}

	munmap(c[0], sb[0].st_size);
	munmap(c[1], sb[1].st_size);

	return(EX_OK);
}
