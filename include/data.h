#include <limits.h>
#include <stdint.h>

/* 4 gives good speed and sane RAM usage */
#define	CMASK	4
/* KEYSIZE must be multiple of CMASK */
#define KEYSIZE	CHAR_BIT*sizeof(((data_t *)0)->k)

typedef struct {
	int64_t		*r;
	int64_t		*d;
} record_t;

struct data_t {
	uint32_t	k;

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
void data_init(data_t *, int, int);
record_t *data_fetch(data_t *, int64_t *, int, int);
void data_iterate(data_t *, void (*)(const record_t *));
