#include <stdint.h>

#define	CMASK	4	/* 4 gives good speed and sane RAM usage */
#define KEYSIZE	32	/* int32_t */

#if KEYSIZE % CMASK
#	error KEYSIZE must be multiple of CMASK
#endif

typedef struct {
	int64_t		*r;
	int64_t		*d;
} record_t;

struct data_t {
	uint32_t	k;

	/* 20% CPU hit, but 30% RAM saving for 10m records */
	struct data_t	**c;

	int		nR;
	record_t	*R;
};
typedef struct data_t data_t;

struct path {
	data_t	*d;
	int	o;
};

data_t *data_newnode(void);
void data_newrecord(data_t *, int, int);
record_t *data_fetch(data_t **, int64_t *, int, int);
void data_iterate(data_t *, void (*)(const record_t *));
