VERSION		:= $(shell git rev-parse --short HEAD)$(shell git diff-files --quiet || printf -- -dirty)
#FLAGS		:= -DVERSION="\"$(VERSION)\""

KERNEL		:= $(shell uname -s)

INCLUDES	+= -Iinclude
CPPFLAGS	+= $(INCLUDES)
CFLAGS		+= -pipe -pedantic -Wall -std=c99 -D_BSD_SOURCE $(INCLUDES)
LDFLAGS		+= -lpthread

ifdef PROFILE
	CFLAGS  += -pg -fprofile-arcs -ftest-coverage
	LDFLAGS += -pg -lgcov -coverage
endif

ifdef NDEBUG
	CFLAGS	+= -DNDEBUG -O3
else
	CFLAGS	+= -g3
endif

# better stripping
CFLAGS	+= -fdata-sections
ifndef PROFILE
	CFLAGS	+= -ffunction-sections
endif
LDFLAGS	+= -Wl,--gc-sections

TARGETS = vm
SOURCES = vm.c data.c murmur3.c

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
	rm -f $(TARGETS) *.o *.d *.d.* gmon.out *.gcov *.gcda *.gcno

vm: $(SOURCES:.c=.o)

%.d: %.c
	@set -e; rm -f $@; \
	 $(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	 sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	 rm -f $@.$$$$

-include $(SOURCES:.c=.d)

%.o: %.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) $(FLAGS) $<

%: %.o
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o $@
ifdef NDEBUG
	$(CROSS_COMPILE)strip $@
endif

.PHONY: all help clean distclean
