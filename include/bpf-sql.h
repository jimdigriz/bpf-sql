#include "bpf.h"

typedef struct {
	int			ncols;
	char			col[10][100];

	enum			{ INVALID, HASH } type;
	int			nkeys;
	int			width;

	struct bpf_program	*prog;
} bpf_sql_t;
