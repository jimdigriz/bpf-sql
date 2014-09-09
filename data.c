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

	assert(desc[0].t != DATA);
	assert(desc[ndesc-1].t == DATA);

	*G = calloc(1, sizeof(struct data));
	if (!*G)
		ERROR0(EX_OSERR, "calloc(*G)");

	switch (desc[0].t) {
	case TRIE:
		(*G)->rR.r.t = calloc(1, sizeof(struct trie));
		if (!(*G)->rR.r.t)
			ERROR0(EX_OSERR, "calloc((*G)->rR.r.t)");
		break;
	default:
		ERRORV(EX_SOFTWARE, "unknown data type: %d", desc[0].t);
	}

	for (int i = 0; i < ndesc; i++)
		(*G)->wR += desc[i].w;

	(*G)->R = calloc(1, (*G)->wR*sizeof(int64_t));
	if (!(*G)->R)
		ERROR0(EX_OSERR, "calloc((*G)->R)");

	(*G)->nd = ndesc;
	(*G)->d = desc;
}

static struct record *trie_fetch(struct trie *t, int64_t *R, int w)
{
	uint32_t key = murmur3_32((char *)R, w*sizeof(int64_t), 0);

	for (int h = 0; h <= KEYSIZE/CMASK; t = &t->c[(key >> (CMASK*h)) & ((1<<CMASK)-1)], h++) {
		if (t->c)
			continue;

		if (t->nR == 0)
			t->Hk = key;

		if (t->Hk == key) {
			int n;

			for (n = 0; n < t->nR; n++)
				if (!memcmp(t->R[n].k, R, w*sizeof(int64_t)))
					return &t->R[n];

			data_addrecord(t, w);
			memcpy(t->R[n].k, R, w*sizeof(int64_t));

			return &t->R[n];
		}

		struct trie **cptr = &t->c;
		*cptr = calloc(1<<CMASK, sizeof(struct trie));
		if (!*cptr)
			ERROR0(EX_OSERR, "calloc(*cptr)");

		int k = (t->Hk >> (CMASK*h)) & ((1<<CMASK)-1);

		t->c[k].Hk = t->Hk;
		t->c[k].nR = t->nR;
		t->c[k].R = t->R;

		t->Hk = 0;
		t->nR = 0;
		t->R = NULL;
	}

	ERROR0(EX_SOFTWARE, "broke out of loop");
}

static struct record *data_fetch(struct data *G)
{
	struct record *R = &G->rR;

	for (int i = 0, o = 0; i < G->nd - 1; i++, o += G->d[i].w) {
		switch (G->d[i].t) {
		case TRIE:
			R = trie_fetch(R->r.t, &G->R[o], G->d[i].w);
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
	int w = G->d[G->nd-1].w;
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
	int w = G->d[G->nd-1].w;
	int o = G->wR - w;

	if (!R->r.d) {
		R->r.d = calloc(w, sizeof(int64_t));
		if (!R->r.d)
			ERROR0(EX_OSERR, "calloc(R->r.d)");
	}

	memcpy(R->r.d, &G->R[o], w*sizeof(int64_t));
}

static void trie_iterate(struct data *,
			const int, const int,
			const struct trie *,
			void (*)(const struct data *, const int64_t *));

static void _data_iterate(struct data *G,
			const int o, const int n,
			const struct record *rR,
			void (*cb)(const struct data *, const int64_t *))
{
	memcpy(&G->R[o], rR->k, G->d[n].w*sizeof(int64_t));

	if (n == G->nd - 2) {
		memcpy(&G->R[G->nd-1], rR->r.d, G->d[G->nd-1].w*sizeof(int64_t));
		cb(G, G->R);
		return;
	}

	switch (G->d[n+1].t) {
	case TRIE:
		trie_iterate(G, o+G->d[n].w, n+1, rR->r.t, cb);
		break;
	default:
		ERRORV(EX_SOFTWARE, "unknown data type: %d", G->d[n+1].t);
	}
}

void data_iterate(struct data *G,
			void (*cb)(const struct data *, const int64_t *))
{
	switch (G->d[0].t) {
	case TRIE:
		trie_iterate(G, 0, 0, G->rR.r.t, cb);
		break;
	default:
		ERRORV(EX_SOFTWARE, "unknown data type: %d", G->d[0].t);
	}
}

static void trie_iterate(struct data *G,
			const int o, const int n,
			const struct trie *t,
			void (*cb)(const struct data *, const int64_t *))
{
	struct {
		const struct trie	*t;
		int			o;
	} path[(KEYSIZE/CMASK) + 1];
	int h = 0;

	path[0].t = t;
	path[0].o = 0;

	while (h > -1) {
		if (path[h].t->nR) {
			for (int i = 0; i < path[h].t->nR; i++)
				_data_iterate(G, o, n, &path[h].t->R[i], cb);

			h--;
			continue;
		}

		if (!path[h].t->c) {
			h--;
			continue;
		}

		while (path[h].o < 1<<CMASK) {
			struct trie *tt = &path[h].t->c[path[h].o];

			path[h].o++;
			h++;

			path[h].t = tt;
			path[h].o = 0;

			break;
		}

		if (path[h].o == 1<<CMASK)
			h--;
	}
}
