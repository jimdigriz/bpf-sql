#include <stdint.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <sysexits.h>
#include <assert.h>
#include <string.h>

#include "data.h"
#include "murmur3.h"

void data_newrecord(data_t *node, int nr, int nd)
{
	int n = node->nR;

	node->R = realloc(node->R, (n+1) * sizeof(record_t));
	if (!node->R)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "realloc(node->R)");

	node->R[n].r = calloc(nr, sizeof(int64_t));
	if (!node->R[n].r)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(node->R[n].r)");

	node->R[n].d = calloc(nd, sizeof(int64_t));
	if (!node->R[n].d)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(node->R[n].d)");

	node->nR++;
}

/* root node is a scratch area */
void data_init(data_t *G, int nr, int nd) {
	assert(KEYSIZE % CMASK == 0);

	data_newrecord(G, nr, nd);
	G->nR = 0;
	G->c = calloc(1<<CMASK, sizeof(data_t));
	if (!G->c)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(G->c)");
}

record_t *data_fetch(data_t *node, int64_t *r, int nr, int nd)
{
	uint32_t key = murmur3_32((char *)r, nr*sizeof(int64_t), 0);

	for (int h = 0; h <= KEYSIZE/CMASK; node = &node->c[(key >> (CMASK*h)) & ((1<<CMASK)-1)], h++) {
		if (node->c)
			continue;

		if (node->nR == 0)
			node->k = key;

		if (node->k == key) {
			int n;

			for (n = 0; n < node->nR; n++)
				if (!memcmp(node->R[n].r, r, nr*sizeof(int64_t)))
					return &node->R[n];

			data_newrecord(node, nr, nd);
			memcpy(node->R[n].r, r, nr*sizeof(int64_t));

			return &node->R[n];
		}

		data_t **cptr = &node->c;
		*cptr = calloc(1<<CMASK, sizeof(data_t));
		if (!*cptr)
			error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(*cptr)");

		int k = (node->k >> (CMASK*h)) & ((1<<CMASK)-1);

		node->c[k].k = node->k;
		node->c[k].nR = node->nR;
		node->c[k].R = node->R;

		node->k = 0;
		node->nR = 0;
		node->R = NULL;
	}

	error_at_line(EX_SOFTWARE, errno, __FILE__, __LINE__, "broke out of loop");
	exit(1);
}

void data_iterate(data_t *node, void (*cb)(const record_t *))
{
	struct path path[(KEYSIZE/CMASK) + 1];
	int h = 0;

	path[0].d = node;
	path[0].o = 0;

	while (h > -1) {
		if (path[h].d->nR) {
			for (int n = 0; n < path[h].d->nR; n++)
				cb(&path[h].d->R[n]);

			h--;
			continue;
		}

		if (!path[h].d->c) {
			h--;
			continue;
		}

		while (path[h].o < 1<<CMASK) {
			data_t *d = &path[h].d->c[path[h].o];

			path[h].o++;
			h++;

			path[h].d = d;
			path[h].o = 0;

			break;
		}

		if (path[h].o == 1<<CMASK)
			h--;
	}
}
