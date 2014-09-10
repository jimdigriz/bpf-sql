Some experiments in grafting a [Berkeley Packet Filter (BPF)](http://en.wikipedia.org/wiki/Berkeley_Packet_Filter) onto a [Column-oriented Database](http://en.wikipedia.org/wiki/Column-oriented_DBMS) and providing an SQL like interface to the user.

Of course this results in some constraints.

Treat the data set as a spreadsheet where each column is an integer metric (use a [map](http://en.wikipedia.org/wiki/Associative_array) for strings) and represented by a separate file.  Each row is a record and its metrics are found at the same location in each file, thus the files all have the same length and record count.

# Preflight

    sudo apt-get install build-essential
    
    git clone https://github.com/jimdigriz/bpf-sql.git
    cd bpf-sql
    ln -f -s programs/filter-by-hour.c program.c
    make help
    make

# Data Preparation

The on-disk format used for each column file is just a raw list of 64bit signed integers stored in big-endian format, so when converting your own data set you can use a tab separated input and some Perl to generate each metric file (named `metricX.bin`):

    cat input_data | perl -ane 'foreach (0..$#F) { open($f[$_], ">", "metric".$_.".bin") if ($.==1); print {$f[$_]} pack "q>", $F[$_] }'

## Generating Fake Data

### Random

The following will generate you a column of data:

    SIZE=8       # 1=8bit, 2=16bit, 4=32bit, 8=64bit
    TYPE=d       # d=integer, u=unsigned int
    NREC=10**8   # number of records you want (100m)

    od -v -An -w$SIZE -t $TYPE$SIZE -N $((SIZE*NREC)) /dev/urandom

# Engine

The engine closely resembles the BPF filtering engine described in the [BSD BPF manpage](http://www.freebsd.org/cgi/man.cgi?bpf(4)) which is closely modelled after the [Steven McCanne's and Van Jacobson's BPF paper](http://usenix.org/publications/library/proceedings/sd93/mccanne.pdf).

    Element            Description
    
    A                  64 bit wide accumulator
    X                  64 bit wide X register
    M[]                BPF_MEMWORDS x 64 bit wide misc registers aka "scratch
                       memory store", addressable from 0 BPF_MEMWORDS-1
    
    C[]                NCOL x 64bit wide read-only column registers that
                       have the current row record data (akin to BPF's P[])
    
    G                  Non-accessible global storage containing results
    R[]                (nkeys+width) x 64bit wide results registers (see below)

The following instructions have had their action slightly amended:

    BPF_LD+BPF_ABS     A <- C[k]
    BPF_LD+BPF_IND     A <- C[X + k]
    
    BPF_RET            Return code unused, for now always zero

**N.B.** all ALU operations are as 64bit signed integer math.  Any unsigned 64bit integers operations as signed 64bit integer is usually safe in that you should be able to cast them back correctly, though only as long as you use the arithmetic operators wisely (ie. avoid `JMP_JG[TE]` and `BPF_NEG`)

The following load/store/find `BPF_REC` (record) instructions have been added:

    BPF_LD+BPF_REC     A <- R[k]
    BPF_ST+BPF_REC     R[k] <- A
    BPF_MISC+BPF_LDR   R <- G
    BPF_MISC+BPF_STR   G <- R

## `R` Register Usage

The `R[]` register is special as it stores records loaded in and from G, and is the set of registers you use to get data into G.  The first `nkeys` registers group together to form an unique tuple that is used to reference a single record whilst the following remaining `width` registers make up the data portion.

For example, if `nkeys` is 2 and `width` is 3, then the following plays out as such:

 1. set the registers `R[0]=7` and `R[1]=2`
 1. call `BPF_MISC+BPF_LDR` to fetch the record, as it does not exist, it is created and initialised to zero
 1. set `R[2]=-10`, set `R[3]=3` and `R[4]=18`
 1. call `BPF_MISC+BPF_STR` to store the record, as it exists, it is updated
 1. call `BPF_RET`

This will in the output create the resulting row:

    7,2,-10,3,18

Where `7,2` make up your key, and `-10,3,18` is the result data associated to it.

### Notes

 * if `BPF_MISC+BPF_LDR` cannot find the record, then the data portion of `R` is initialised to zero
 * if you call `BPF_RET` before calling `BPF_MISC+BPF_STR`, your changes are discarded
 * records cannot be deleted once created
 * you *can* create and update several records for a single run of your program over `C[]`

# TODO

In roughly order of importance:

 * only create records in `G` when `BPF_MISC+BPF_STR` is called, not when `BPF_MISC+BPF_LDR` is
 * would it be helpful to be able to distingush between record existing or not, and how that would be done
 * tool to generate mock data to experiment with
 * add stepping debugging support
 * improve the profiling visibility
 * frequency analysis
 * [element distinctness/uniqueness](http://en.wikipedia.org/wiki/Element_distinctness_problem)
 * intersection analysis (Venn)
 * [INT32-C. Ensure that operations on signed integers do not result in overflow](https://www.securecoding.cert.org/confluence/display/seccode/INT32-C.+Ensure+that+operations+on+signed+integers+do+not+result+in+overflow) - maybe look to OS X's [checkint(3)](https://developer.apple.com/library/mac/documentation/Darwin/Reference/Manpages/man3/checkint.3.html)
 * alternative engine primitives, BPF not well suited due to all the indirect pointer dereferencing everywhere maybe?
     * [colorForth](http://www.colorforth.com/forth.html)
     * [Subroutine threading](http://www.cs.toronto.edu/~matz/dissertation/matzDissertation-latex2html/node7.html) especially [Speed of various interpreter dispatch techniques](http://www.complang.tuwien.ac.at/forth/threading/)
 * SQL to BPF converter
 * BPF checker to simplify the engine
 * BPF optimiser
 * steroids:
     * [What Every Programmer Should Know About Memory](http://www.akkadia.org/drepper/cpumemory.pdf) (and [What Every Computer Scientist Should Know About Floating Point Arithmetic](http://cr.yp.to/2005-590/goldberg.pdf))
     * [`malloc()` tuning](http://www.gnu.org/software/libc/manual/html_node/Malloc-Tunable-Parameters.html)
     * [`posix_madvise()`](http://www.freebsd.org/cgi/man.cgi?posix_madvise(2))
     * [GCC Optimization's](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
         * [Performance Tuning with GCC](http://www.redhat.com/magazine/011sep05/features/gcc/)
         * [`-ffast-math` and `-Ofast`](http://programerror.com/2009/09/when-gccs-ffast-math-isnt/)
         * [GCC x86 performance hints](https://software.intel.com/en-us/blogs/2012/09/26/gcc-x86-performance-hints)
         * [`-freorder-blocks-and-partition`, `-fno-common`, `-fno-zero-initialized-in-bss`](http://blog.mozilla.org/tglek/2010/03/05/mirror-mirror-on-the-wall-why-is-my-binary-slow/)
     * [Profile Guided Optimisations (PGO) - using `-fprofile-generate` and `-fprofile-use`](http://blog.mozilla.org/tglek/2010/04/12/squeezing-every-last-bit-of-performance-out-of-the-linux-toolchain/)
     * [`__builtin_prefetch`](https://gcc.gnu.org/onlinedocs/gcc-3.3.6/gcc/Other-Builtins.html#index-g_t_005f_005fbuiltin_005fprefetch-1861)
     * [Auto-vectorization with gcc 4.7](http://locklessinc.com/articles/vectorize/)
 * investigate [Blosc](http://www.blosc.org/) and its [c-blosc](https://github.com/Blosc/c-blosc) library
 * support an approximation 'turbo' [Zipfian](http://en.wikipedia.org/wiki/Zipf's_law) mode and use [sketches](http://en.wikipedia.org/wiki/Sketch_(mathematics)):
     * [Count-Min](https://sites.google.com/site/countminsketch/)
     * [K-minimum Values](http://research.neustar.biz/2012/07/09/sketch-of-the-day-k-minimum-values/)
     * [HyperLogLog](http://research.neustar.biz/2012/10/25/sketch-of-the-day-hyperloglog-cornerstone-of-a-big-data-infrastructure/)
