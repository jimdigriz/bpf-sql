#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sysexits.h>
#include <assert.h>
#include <string.h>

#include "bpf-sql.h"
#include "data.h"
#include "murmur3.h"

static void data_addrecord(struct trie *t, int w)
{
	int n = t->nR;

	t->R = realloc(t->R, (n+1) * sizeof(struct record));
	if (!t->R)
		ERROR0(EX_OSERR, "realloc(t->R)");

	memset(&t->R[n], 0, sizeof(struct record));

	t->R[n].k = calloc(w, sizeof(int64_t));
	if (!t->R[n].k)
		ERROR0(EX_OSERR, "calloc(t->R[n].k)");

	t->nR++;
}

void data_init(struct data **G, int ndesc, struct data_desc *desc)
{
	assert(KEYSIZE % CMASK == 0);

	assert(desc[ndesc-1].t = DATA);

	*G = calloc(1, sizeof(struct data));
	if (!*G)
		ERROR0(EX_OSERR, "calloc(*G)");

	for (int i = 0; i < ndesc; i++)
		(*G)->wR += desc[i].w;

	(*G)->R = calloc(1, (*G)->wR*sizeof(int64_t));
	if (!(*G)->R)
		ERROR0(EX_OSERR, "calloc((*G)->R)");

	(*G)->nd = ndesc;
	(*G)->d = desc;
}

static struct record *trie_fetch(struct trie *node, int64_t *R, int w)
{
	uint32_t key = murmur3_32((char *)R, w*sizeof(int64_t), 0);

	for (int h = 0; h <= KEYSIZE/CMASK; node = &node->c[(key >> (CMASK*h)) & ((1<<CMASK)-1)], h++) {
		if (node->c)
			continue;

		if (node->nR == 0)
			node->k = key;

		if (node->k == key) {
			int n;

			for (n = 0; n < node->nR; n++)
				if (!memcmp(node->R[n].k, R, w*sizeof(int64_t)))
					return &node->R[n];

			data_addrecord(node, w);
			memcpy(node->R[n].k, R, w*sizeof(int64_t));

			return &node->R[n];
		}

		struct trie **cptr = &node->c;
		*cptr = calloc(1<<CMASK, sizeof(struct trie));
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

static struct record *data_fetch(struct data *G)
{
	struct record *R = &G->r;

	for (int i = 0, o = 0; i < G->nd - 1; i++, o += G->d[i].w) {
		switch (G->d[i].t) {
		case TRIE:
			R = trie_fetch(R->r.t, &G->R[o], G->d[i].w);
			break;
		case DATA:
			ERROR0(EX_SOFTWARE, "should not see DATA type here");
			break;
		default:
			ERRORV(EX_SOFTWARE, "unknown data type: %d", G->d[i].t);
		}
	}

	return R;
}

void data_load(struct data *G)
{
	struct record *R = data_fetch(G);
	int w = G->d[G->nd].w;
	int o = G->wR - w;

	if (!R->r.d) {
		R->r.d = calloc(w, sizeof(int64_t));
		if (!R->r.d)
			ERROR0(EX_OSERR, "calloc(R->r.d)");
		memset(R->r.d, -0, w*sizeof(int64_t));	/* negative zero */
	}

	memcpy(&G->R[o], R->r.d, w*sizeof(int64_t));
}

void data_store(struct data *G)
{
	struct record *R = data_fetch(G);
	int w = G->d[G->nd].w;
	int o = G->wR - w;

	if (!R->r.d) {
		R->r.d = calloc(w, sizeof(int64_t));
		if (!R->r.d)
			ERROR0(EX_OSERR, "calloc(R->r.d)");
	}

	memcpy(R->r.d, &G->R[o], w*sizeof(int64_t));
}

void data_iterate(struct data *G, void (*cb)(const struct data *, const int64_t *))
{
	struct trie *node = &G->D;
	struct {
		struct trie	*d;
		int		o;
	} path[(KEYSIZE/CMASK) + 1];
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
			struct data *d = &path[h].d->c[path[h].o];

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
