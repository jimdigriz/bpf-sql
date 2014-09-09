#include <limits.h>
#include <stdint.h>

#ifndef __BPF_SQL_DATA_H__
#define __BPF_SQL_DATA_H__

/* 4 gives good speed and sane RAM usage */
#define	CMASK	4
/* KEYSIZE must be multiple of CMASK */
#define KEYSIZE	CHAR_BIT*sizeof(((struct record *)0)->k)

struct record {
	int64_t			*k;	/* key */

	union {
		struct trie	*t;	/* TRIE */
		int64_t		*d;	/* DATA - actual data */
	}			r;	/* record */
};

struct data_desc {
	enum {
		TRIE,
		DATA,			/* 'end' componment (NON ZERO!) */
	}			t;	/* type */
	int			w;	/* width */
};

struct data {
	struct record		rR;	/* root record */

	int64_t			wR;	/* R register width */
	int64_t			*R;	/* R register */

	int			nd;	/* number of desc */
	struct data_desc	*d;	/* record description */
};

struct trie {
	uint32_t		Hk;	/* H(key) */

	struct trie		*c;	/* children */

	int			nR;	/* number of records */
	struct record		*R;	/* records */
};

void data_init(struct data **, int, struct data_desc *);
void data_load(struct data *);
void data_store(struct data *);
void data_iterate(struct data *, void (*)(const struct data *, const int64_t *));

#endif	/* __BPF_SQL_DATA_H__ */
