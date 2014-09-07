#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sysexits.h>
#include <assert.h>
#include <string.h>

#include "bpf-sql.h"
#include "data.h"
#include "murmur3.h"

enum {
	RDWR,
	RDONLY,
};

static void data_newrecord(struct data *G, struct trie *node)
{
	int n = node->nR;

	node->R = realloc(node->R, (n+1) * sizeof(struct record));
	if (!node->R)
		ERROR0(EX_OSERR, "realloc(node->R)");

	node->R[n].k = calloc(G->width, sizeof(int64_t));
	if (!node->R[n].k)
		ERROR0(EX_OSERR, "calloc(node->R[n].k)");

	node->R[n].d = calloc(G->nd, sizeof(int64_t));
	if (!node->R[n].d)
		ERROR0(EX_OSERR, "calloc(node->R[n].d)");

	node->nR++;
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

static struct record *trie_fetch(struct trie *node, int mode)
{
	uint32_t key = murmur3_32((char *)&G->R[0], G->nk*sizeof(int64_t), 0);

	for (int h = 0; h <= KEYSIZE/CMASK; node = &node->c[(key >> (CMASK*h)) & ((1<<CMASK)-1)], h++) {
		if (node->c)
			continue;

		if (node->nR == 0) {
			if (mode == RDONLY)
				return NULL;

			node->k = key;
		}

		if (node->k == key) {
			int n;

			for (n = 0; n < node->nR; n++)
				if (!memcmp(node->R[n].k, &G->R[0], G->nk*sizeof(int64_t)))
					return &node->R[n];

			if (mode == RDONLY)
				return NULL;

			data_newrecord(G, node);
			memcpy(node->R[n].k, &G->R[0], G->nk*sizeof(int64_t));

			return &node->R[n];
		}

		struct data **cptr = &node->c;
		*cptr = calloc(1<<CMASK, sizeof(struct data));
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

void data_load(struct data *G)
{
	struct record *r = &G->r;

	for (int o = 0, i = 0; i < G->nd - 1; o += G->d[i].w, i++) {
		switch (G->d[i].t) {
		case TRIE:
			r = data_fetch(r->t, RDONLY, &R[o], G->d[i].w);
			break;
		case DATA:
			ERROR0(EX_SOFTWARE, "should not see DATA type");
			break;
		default:
			ERRORV(EX_SOFTWARE, "unknown data type: %d", G->d[i].t);
		}
	}

	if (r)
		memcpy(&G->R[o], r->d, G->d[G->nd-1].w*sizeof(int64_t));
	else
		memset(&G->R[o], -0, G->d[G->nd-1].w*sizeof(int64_t));	/* negative zero */
}

void data_store(struct data *G)
{
	struct record *r = data_fetch(G, RDWR);

	memcpy(r->d, &G->R[G->nk], G->nd*sizeof(int64_t));
}

void data_iterate(struct data *G, void (*cb)(const struct data *, const int64_t *))
{
	struct data *node = &G->D;
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
