#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <err.h>

#include "bpf.h"
#include "data.h"

#ifndef __BPF_SQL_BPF_SQL_H__
#define __BPF_SQL_BPF_SQL_H__

#define	ARRAY_SIZE(x)			(sizeof(x)/sizeof(x[0]))

#define	ERROR0(exitcode, format)	err(exitcode, "[%s:%d] " format, __FILE__, __LINE__)
#define	ERRORV(exitcode, format, ...)	err(exitcode, "[%s:%d] " format, __FILE__, __LINE__, __VA_ARGS__)

struct column {
	char			*filename;
	int			fd;
	struct stat		sb;
	int64_t 			*m;
	int64_t			*C;
};

struct bpf_sql {
	int			ndesc;
	struct data_desc	*desc;

	struct bpf_program	*prog;

	int			ncols;
	struct column		*col;
};

#endif	/* __BPF_SQL_BPF_SQL_H__ */
