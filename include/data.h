#include <stdint.h>

#define	CMASK	8
#define KEYSIZE	64	/* int64_t */

#if KEYSIZE % CMASK
#	error KEYSIZE must be multiple of CMASK
#endif

struct data_t {
	uint64_t	k;

	struct data_t	*c[2<<CMASK];

	int64_t		*r;
	int64_t		*d;
};
typedef struct data_t data_t;

extern int NTRACK;
extern data_t **TRACK;

data_t *data_newnode(void);
void data_newpayload(data_t *, int, int);
data_t *data_fetch(data_t **, int64_t *, int, int);
