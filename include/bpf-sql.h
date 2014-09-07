#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bpf.h"

#define	ARRAY_SIZE(x)	(sizeof(x)/sizeof(x[0]))

typedef struct {
	char		*filename;
	int		fd;
	struct stat	sb;
	int64_t 	*m;
	int64_t		*C;
} column_t;

typedef struct {
	int			nkeys;
	int			width;

	struct bpf_program	*prog;

	int			ncols;
	column_t		*col;
} bpf_sql_t;
