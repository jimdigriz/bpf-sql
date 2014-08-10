#include <stdint.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <sysexits.h>
#include <assert.h>
#include <string.h>

#include "data.h"
#include "murmur3.h"

data_t *data_newnode(void)
{
	data_t *d;

	d = calloc(1, sizeof(data_t));
	if (!d)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(d)");

	return d;
}

void data_newrecord(data_t *d, int nr, int nd)
{
	int n = d->nR;

	d->R = realloc(d->R, (n+1) * sizeof(record_t));
	if (!d->R)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "realloc(d->R)");

	d->R[n].r = calloc(nr, sizeof(int64_t));
	if (!d->R[n].r)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(d->R[n].r)");

	d->R[n].d = calloc(nd, sizeof(int64_t));
	if (!d->R[n].d)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(d->R[n].d)");

	d->nR++;
}

int NTRACK = 0;
record_t **TRACK = NULL;

record_t *data_fetch(data_t **node, int64_t *r, int nr, int nd)
{
	uint32_t key;
	data_t *tnode;
	int h = 0;

	key = (nr == 1)
		? nr
		: murmur3_32((char *)r, nr*sizeof(int64_t), 0);

	while (1) {
		if (!*node) {
			*node = data_newnode();
			(*node)->k = key;

			data_newrecord(*node, nr, nd);
			memcpy((*node)->R[0].r, r, nr*sizeof(int64_t));

			TRACK = realloc(TRACK, (NTRACK+1)*sizeof(record_t *));
			if (!TRACK)
				error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "realloc(TRACK)");
			TRACK[NTRACK] = &(*node)->R[0];
			NTRACK++;

			return &(*node)->R[0];
		}

		if ((*node)->k == key) {
			for (int i = 0; i<(*node)->nR; i++) {
				if (memcmp((*node)->R[i].r, r, nr*sizeof(int64_t)) == 0)
					return &(*node)->R[i];
			}

			data_newrecord(*node, nr, nd);
			memcpy((*node)->R[(*node)->nR-1].r, r, nr*sizeof(int64_t));

			TRACK = realloc(TRACK, (NTRACK+1)*sizeof(record_t *));
			if (!TRACK)
				error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "realloc(TRACK)");
			TRACK[NTRACK] = &(*node)->R[(*node)->nR-1];
			NTRACK++;

			return &(*node)->R[(*node)->nR-1];
		}

		if ((*node)->k) {
			tnode = data_newnode();

			tnode->k = (*node)->k;
			tnode->nR = (*node)->nR;
			tnode->R = (*node)->R;

			(*node)->k = 0;
			(*node)->c[(tnode->k >> (CMASK*h)) & ((1<<CMASK)-1)] = tnode;
			(*node)->nR = 0;
			(*node)->R = NULL;
		}

		node = &(*node)->c[(key >> (CMASK*h)) & ((1<<CMASK)-1)];
		h++;
	}
}
