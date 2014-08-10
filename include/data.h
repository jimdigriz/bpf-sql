#include <stdint.h>

#define	CMASK	4
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

	struct data_t	*c[1<<CMASK];

	int		nR;
	record_t	*R;
};
typedef struct data_t data_t;

extern int NTRACK;
extern record_t **TRACK;

data_t *data_newnode(void);
void data_newrecord(data_t *, int, int);
record_t *data_fetch(data_t **, int64_t *, int, int);
