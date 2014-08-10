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

int NTRACK = 0;
record_t **TRACK = NULL;

void data_newrecord(data_t *d, int nr, int nd)
{
	int n = d->nR;
	int r = -1;

	if (d->R) {
		for (r = 0; r < NTRACK; r++)
			for (int i = 0; i < n; i++)
				if (TRACK[r] == &d->R[i])
					TRACK[r] = 0;
	}

	d->R = realloc(d->R, (n+1) * sizeof(record_t));
	if (!d->R)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "realloc(d->R)");

	if (r != -1) {
		r = 0;
		for (int i = 0; i < n; i++)
			for (; r < NTRACK; r++)
				if (TRACK[r] == 0) {
					TRACK[r] = &d->R[i];
					break;
				}
	}
	
	TRACK = realloc(TRACK, (NTRACK+1)*sizeof(record_t *));
	if (!TRACK)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "realloc(TRACK)");
	TRACK[NTRACK] = &d->R[n];
	NTRACK++;

	d->R[n].r = calloc(nr, sizeof(int64_t));
	if (!d->R[n].r)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(d->R[n].r)");

	d->R[n].d = calloc(nd, sizeof(int64_t));
	if (!d->R[n].d)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(d->R[n].d)");

	d->nR++;
}

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

			return &(*node)->R[0];
		}

		if ((*node)->k == key) {
			int n;

			for (n = 0; n < (*node)->nR; n++)
				if (!memcmp((*node)->R[n].r, r, nr*sizeof(int64_t)))
					return &(*node)->R[n];

			data_newrecord(*node, nr, nd);
			memcpy((*node)->R[n].r, r, nr*sizeof(int64_t));

			return &(*node)->R[n];
		}

		if ((*node)->k) {
			tnode = data_newnode();

			tnode->k = (*node)->k;
			tnode->nR = (*node)->nR;
			tnode->R = (*node)->R;

			(*node)->k = 0;
			(*node)->c = calloc(1<<CMASK, sizeof(data_t *));
			if (!(*node)->c)
				error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc((*node)->c)");
			(*node)->c[(tnode->k >> (CMASK*h)) & ((1<<CMASK)-1)] = tnode;
			(*node)->nR = 0;
			(*node)->R = NULL;
		}

		node = &(*node)->c[(key >> (CMASK*h)) & ((1<<CMASK)-1)];
		h++;
	}
}
