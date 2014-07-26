#include "bpf.h"

typedef struct {
	int			ncols;
	char			col[10][100];

	int			nkeys;
	int			width;

	struct bpf_program	*prog;
} bpf_sql_t;
