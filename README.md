Some experiments in grafting a [Berkeley Packet Filter (BPF)](http://en.wikipedia.org/wiki/Berkeley_Packet_Filter) onto a [Column-oriented Database](http://en.wikipedia.org/wiki/Column-oriented_DBMS) and providing an SQL like interface to the user.

Of course this results in some constraints.

Treat the dataset as a spreadsheet where each column is an integer metric (use a [map](http://en.wikipedia.org/wiki/Associative_array) for strings) and represented by a separate file.  Each rows is a record where its metrics are found at the same location in each file.  This results in all the files having the same length and of course record count.

# Preflight

    sudo apt-get install build-essential uthash-dev
    
    git clone https://github.com/jimdigriz/bpf-sql.git
    cd bpf-sql
    make

# Data Preparation

The on-disk format used for each column file is just a raw list of 64bit signed integers stored in big-endian format, so when converting your own dataset you can use a tab separated input and some Perl to generate each metric file:

    cat input_data | perl -pe '$_ = pack "q>", (split /\s+/)[0]' > metric0.bin
    cat input_data | perl -pe '$_ = pack "q>", (split /\s+/)[1]' > metric1.bin
    ...

**N.B.** unsigned 64bit integer to signed 64bit integer is usually safe in that you should be able to cast them back, though only as long as you use the arithmetic operators wisely (ie. avoid `JMP_JG[TE]` and `BPF_NEG`)

## Generating Fake Data

### Random

The following will generate you roughly 1m/sec rows:

    SIZE=8	# 1=8bit, 2=16bit, 4=32bit, 8=64bit
    TYPE=d	# d=integer, u=unsigned int
    NREC=10**8	# number of records you want (100m)

    od -v -An -w$SIZE -t $TYPE$SIZE -N $((SIZE*NREC)) /dev/urandom

# Engine

The engine closely resembles the BPF filtering engine described in the [BSD BPF manpage](http://www.freebsd.org/cgi/man.cgi?bpf(4)) which is closely modelled after the [Steven McCanne's and Van Jacobson's BPF paper](http://usenix.org/publications/library/proceedings/sd93/mccanne.pdf).

    Element           Description

    A                 64 bit wide accumulator
    X                 64 bit wide X register
    M[]               BPF_MEMWORDS x 64 bit wide misc registers aka "scratch
                      memory store", addressable from 0 BPF_MEMWORDS-1
    
    C[]               NCOL x 64bit wide read-only column registers that
                      have the current row record data (akin to BPF's P[])
    R[]               RCOL x 64bit wide registers to create/replace records

    G                 Global storage containing results

The following instructions have had their action slightly amended:

    BPF_LD+BPF_ABS    A <- C[k]
    BPF_LD+BPF_IND    A <- C[X + k]

    BPF_RET           Non-zero adds/replaces R[] in G

**N.B.** all operations are as 64bit signed integer math

The following load/store/find `BPF_REC` (record) instructions have been added:

    BPF_LD+BPF_REC    A <- R[k]
    BPF_ST+BPF_REC    R[k] <- A

    BPF_MISC+BPF_LDR  Fetch R[] from G and remove it

# TODO

In roughly order of importance:

 * tool to generate mock data to experiment with
 * remove `HACK` and make everything more dynamic
 * improve the profiling support
 * add stepping debugging support
 * frequency analysis
 * intersection analysis (Venn)
 * alternative engine primitives, BPF not well suited due to all the indirects?
     * [colorForth](http://www.colorforth.com/forth.html)
     * [Subroutine threading](http://www.cs.toronto.edu/~matz/dissertation/matzDissertation-latex2html/node7.html) especially [Speed of various interpreter dispatch techniques](http://www.complang.tuwien.ac.at/forth/threading/)
 * SQL to BPF converter
 * BPF checker to simplify the engine
 * BPF optimiser
 * steroids:
     * [`posix_madvise()`](http://www.freebsd.org/cgi/man.cgi?posix_madvise(2))
     * [GCC Optimization's](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
     * [`__builtin_prefetch`](https://gcc.gnu.org/onlinedocs/gcc-3.3.6/gcc/Other-Builtins.html#index-g_t_005f_005fbuiltin_005fprefetch-1861)
 * investigate [Blosc](http://www.blosc.org/) and its [c-blosc](https://github.com/Blosc/c-blosc) library
 * support an approximation 'turbo' [Zipfian](http://en.wikipedia.org/wiki/Zipf's_law) mode and use [sketches](http://en.wikipedia.org/wiki/Sketch_(mathematics)):
     * [Count-Min](https://sites.google.com/site/countminsketch/)
     * [K-minimun Values](http://research.neustar.biz/2012/07/09/sketch-of-the-day-k-minimum-values/)
     * [HyperLogLog](http://research.neustar.biz/2012/10/25/sketch-of-the-day-hyperloglog-cornerstone-of-a-big-data-infrastructure/)
