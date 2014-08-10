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

		if ((*node)->nR && (*node)->k == key) {
			int n;

			for (n = 0; n < (*node)->nR; n++)
				if (!memcmp((*node)->R[n].r, r, nr*sizeof(int64_t)))
					return &(*node)->R[n];

			data_newrecord(*node, nr, nd);
			memcpy((*node)->R[n].r, r, nr*sizeof(int64_t));

			return &(*node)->R[n];
		}

		if ((*node)->nR) {
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

void data_iterate(data_t *node, void (*cb)(const record_t *))
{
	struct path path[KEYSIZE/CMASK];
	int h = 0;

	path[0].d = node;
	path[0].o = 0;

	while (h > -1) {
		if (path[h].d->k) {
			for (int n = 0; n < path[h].d->nR; n++)
				cb(&path[h].d->R[n]);
			h--;
			continue;
		}

		while (path[h].o < KEYSIZE/CMASK) {
			data_t *d = path[h].d->c[path[h].o];

			path[h].o++;

			if (!d)
				continue;

			h++;
			path[h].d = d;
			path[h].o = 0;
			break;
		}

		if (path[h].o == KEYSIZE/CMASK)
			h--;
	}
}
