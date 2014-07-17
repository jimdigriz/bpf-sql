VERSION	= $(shell git rev-parse --short HEAD)$(shell git diff-files --quiet || printf -- -dirty)
#FLAGS	= -DVERSION="\"$(VERSION)\""

KERNEL  = $(shell uname -s)

CFLAGS  = -pipe -pedantic -Wall -std=c99 -D_BSD_SOURCE -Iinclude
LDFLAGS	= -lpthread

ifdef PROFILE
	CFLAGS  += -pg
	LDFLAGS += -pg
endif

ifdef NDEBUG
	CFLAGS	+= -O3
else
	CFLAGS	+= -g3
endif

# better stripping
CFLAGS	+= -fdata-sections
ifndef PROFILE
CFLAGS	+= -ffunction-sections
endif
LDFLAGS	+= -Wl,--gc-sections

TARGETS	= vm
OBJS	= vm.o

all: $(TARGETS)

help:
	@echo 'Cleaning:'
	@echo '  clean                  - clean'
	@echo '  distclean              - clean everything'
	@echo
	@echo 'Run:'
	@echo '  all                    - build all src'
	@echo
	@echo 'See README.md for further details'

distclean: clean

clean:
	rm -f $(TARGETS) $(OBJS)

vm: vm.o

%.o: %.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) $(FLAGS) $<

%: %.o
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o $@
ifdef NDEBUG
	$(CROSS_COMPILE)strip $@
endif

.PHONY: all help clean distclean
