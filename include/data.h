#include <limits.h>
#include <stdint.h>

#ifndef __BPF_SQL_DATA_H__
#define __BPF_SQL_DATA_H__

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

	int			wR;	/* R register width */
	int64_t			*R;	/* R register */

	int			nd;	/* number of desc */
	struct data_desc	*d;	/* record description */

	struct {
		int		records;

		int		tries;

		int		records_in_tries;
		int		sum_trie_depth;
	} stats;
};

/* KEYSIZE must be multiple of CMASK */
#define KEYSIZE		(CHAR_BIT*sizeof(((struct trie *)0)->Hk))

/* TUNEABLES */
/* how deep do you like your trie, lower makes it deeper */
/* 4 gives good speed and sane RAM usage at 10m records */
#define	CMASK		4
/* max trie depth at expense of collisions */
/* 8 has no speed penalty at 10m records at half the RAM */
#define KEYSHIFT	8;

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
