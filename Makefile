VERSION		:= $(shell git rev-parse --short HEAD)$(shell git diff-files --quiet || printf -- -dirty)
#FLAGS		:= -DVERSION="\"$(VERSION)\""

KERNEL		:= $(shell uname -s)

INCLUDES	+= -Iinclude
CPPFLAGS	+= $(INCLUDES)
CFLAGS		+= -pipe -pedantic -Wall -std=c99 -D_BSD_SOURCE $(INCLUDES)
LDFLAGS		+= -lpthread

ifdef PROFILE
	CFLAGS  += -pg -fprofile-generate -ftest-coverage
	LDFLAGS += -pg -lgcov -coverage
endif

ifdef NDEBUG
	CFLAGS	+= -DNDEBUG -O3
else
	CFLAGS	+= -g3 -fstack-protector-all
endif

# better stripping
CFLAGS	+= -fdata-sections
ifndef PROFILE
	CFLAGS	+= -ffunction-sections
endif
LDFLAGS	+= -Wl,--gc-sections

TARGETS = vm
SOURCES = vm.c program.c data.c murmur3.c engine.c

all: $(TARGETS)

help:
	@echo 'Cleaning:'
	@echo '  clean                  - clean'
	@echo '  distclean              - clean everything'
	@echo
	@echo 'Run:'
	@echo '  all                    - build all src'
	@echo
	@echo 'Build Options:'
	@echo '  [default]: debug/assert=on, optimise=off, strip=off, profiling=off'
	@echo '  PROFILE=1: profiling=on'
	@echo '   NDEBUG=1: debug/assert=off, optimise=on, strip=on'
	@echo
	@echo 'See README.md for further details'

distclean: clean
	rm -f gmon.out *.gcov *.gcda *.gcno

clean:
	rm -f $(TARGETS) *.o *.d

vm: $(SOURCES:.c=.o)

%.d: %.c
	@set -e; rm -f $@; \
	 $(CC) -M $(CPPFLAGS) $< > $@.$$$$; \
	 sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	 rm -f $@.$$$$

ifeq (,$(filter $(MAKECMDGOALS),clean distclean))
-include $(SOURCES:.c=.d)
endif

%.o: %.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) $(FLAGS) $<

%: %.o
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o $@
ifdef NDEBUG
	$(CROSS_COMPILE)strip $@
endif

.PHONY: all help clean distclean
