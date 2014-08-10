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

void data_newpayload(data_t *d, int nr, int nd)
{
	d->r = calloc(nr, sizeof(int64_t));
	if (!d->r)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(d->r)");

	d->d = calloc(nd, sizeof(int64_t));
	if (!d->d)
		error_at_line(EX_OSERR, errno, __FILE__, __LINE__, "calloc(d->d)");
}

int NTRACK = 0;
data_t **TRACK = NULL;

data_t *data_fetch(data_t **node, int64_t *r, int nr, int nd)
{
	uint32_t hash[4];
	uint64_t key;
	data_t *tnode = NULL;
	int h = 0;

	MurmurHash3_128(r, nr*sizeof(int64_t), 0, &hash);
	key = hash[0] + ((uint64_t)hash[1] << 32);

	while (1) {
		if (!*node) {
			*node = data_newnode();
			data_newpayload(*node, nr, nd);
			(*node)->k = key;
			memcpy((*node)->r, r, nr*sizeof(int64_t));

			TRACK = realloc(TRACK, (NTRACK+1)*sizeof(data_t *));
			TRACK[NTRACK] = *node;
			NTRACK++;

			return *node;
		}

		if ((*node)->k == key) {
			assert(memcmp(r, (*node)->r, nr*sizeof(int64_t)) == 0);
			return *node;
		}

		if ((*node)->k) {
			tnode = data_newnode();

			tnode->k = (*node)->k;
			tnode->r = (*node)->r;
			tnode->d = (*node)->d;

			(*node)->k = 0;
			(*node)->c[(tnode->k >> (CMASK*h)) & ((2<<CMASK)-1)] = tnode;
			(*node)->r = 0;
			(*node)->d = 0;

			for (int i = 0; i<NTRACK; i++) {
				if (TRACK[i] == *node) {
					TRACK[i] = tnode;
					break;
				}
			}
		}

		tnode = *node;
		node = &((*node)->c[(key >> (CMASK*h)) & ((2<<CMASK)-1)]);
		h++;
	}
}
