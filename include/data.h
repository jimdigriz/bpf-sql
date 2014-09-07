#include <limits.h>
#include <stdint.h>

/* 4 gives good speed and sane RAM usage */
#define	CMASK	4
/* KEYSIZE must be multiple of CMASK */
#define KEYSIZE	CHAR_BIT*sizeof(((data_t *)0)->k)

typedef struct {
	int64_t		*k;
	int64_t		*d;
} record_t;

struct data_t {
	uint32_t	k;

	struct data_t	*c;

	int		nR;
	record_t	*R;
};
typedef struct data_t data_t;

struct datag_t {
	struct data_t	D;

	int64_t		*R;

	int		nk;
	int		nd;
};
typedef struct datag_t datag_t;

struct path {
	data_t	*d;
	int	o;
};

void data_init(datag_t **, int, int);
void data_load(datag_t *);
void data_store(datag_t *);
void data_iterate(datag_t *, void (*)(const record_t *));
