#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sysexits.h>
#include <assert.h>
#include <string.h>

#include "bpf-sql.h"
#include "data.h"
#include "murmur3.h"

#define	READONLY	1

static void data_newrecord(datag_t *G, data_t *node)
{
	int n = node->nR;

	node->R = realloc(node->R, (n+1) * sizeof(record_t));
	if (!node->R)
		ERROR0(EX_OSERR, "realloc(node->R)");

	node->R[n].k = calloc(G->nk, sizeof(int64_t));
	if (!node->R[n].k)
		ERROR0(EX_OSERR, "calloc(node->R[n].k)");

	node->R[n].d = calloc(G->nd, sizeof(int64_t));
	if (!node->R[n].d)
		ERROR0(EX_OSERR, "calloc(node->R[n].d)");

	node->nR++;
}

void data_init(datag_t **G, int nk, int nd) {
	assert(KEYSIZE % CMASK == 0);

	*G = calloc(1, sizeof(datag_t));
	if (!*G)
		ERROR0(EX_OSERR, "calloc(*G)");

	(*G)->R = calloc(1, (nk+nd)*sizeof(int64_t));
	if (!(*G)->R)
		ERROR0(EX_OSERR, "calloc((*G)->R)");

	(*G)->nk = nk;
	(*G)->nd = nd;
}

static record_t *data_fetch(datag_t *G, int mode)
{
	data_t *node = &G->D;
	uint32_t key = murmur3_32((char *)&G->R[0], G->nk*sizeof(int64_t), 0);

	for (int h = 0; h <= KEYSIZE/CMASK; node = &node->c[(key >> (CMASK*h)) & ((1<<CMASK)-1)], h++) {
		if (node->c)
			continue;

		if (node->nR == 0) {
			if (mode == READONLY)
				return NULL;

			node->k = key;
		}

		if (node->k == key) {
			int n;

			for (n = 0; n < node->nR; n++)
				if (!memcmp(node->R[n].k, &G->R[0], G->nk*sizeof(int64_t)))
					return &node->R[n];

			if (mode == READONLY)
				return NULL;

			data_newrecord(G, node);
			memcpy(node->R[n].k, &G->R[0], G->nk*sizeof(int64_t));

			return &node->R[n];
		}

		data_t **cptr = &node->c;
		*cptr = calloc(1<<CMASK, sizeof(data_t));
		if (!*cptr)
			ERROR0(EX_OSERR, "calloc(*cptr)");

		int k = (node->k >> (CMASK*h)) & ((1<<CMASK)-1);

		node->c[k].k = node->k;
		node->c[k].nR = node->nR;
		node->c[k].R = node->R;

		node->k = 0;
		node->nR = 0;
		node->R = NULL;
	}

	ERROR0(EX_SOFTWARE, "broke out of loop");
	exit(1);
}

void data_iterate(datag_t *G, void (*cb)(const record_t *))
{
	data_t *node = &G->D;
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

void data_load(datag_t *G)
{
	record_t *r = data_fetch(G, READONLY);
	if (r)
		memcpy(&G->R[G->nk], r->d, G->nd*sizeof(int64_t));
}

void data_store(datag_t *G)
{
	record_t *r = data_fetch(G, 0);
	memcpy(r->d, &G->R[G->nk], G->nd*sizeof(int64_t));
}
