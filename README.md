Some experiments in grafting a [Berkeley Packet Filter (BPF)](http://en.wikipedia.org/wiki/Berkeley_Packet_Filter) onto a [Column-oriented Database](http://en.wikipedia.org/wiki/Column-oriented_DBMS) and providing an SQL like interface to the user.

# Preflight

    sudo apt-get install build-essential uthash-dev
    
    git clone https://github.com/jimdigriz/bpf-sql.git
    cd bpf-sql
    make

## Dry-Run

Lets get a tab seperated TIM,TV2NSPID sample:

    psp-read /psp-data/day16265/psval{TIM,TV2NSPID,...}.psp | gzip -c > day16265.gz

Break out each field and convert it to network ordered (big-endian) 64bit signed values:

    # network order (uint64 -> int64 is preserved bitwise)
    zcat day16265.gz | perl -pe '$_ = pack "q>", (split /\s+/)[0]' > day16265.tim.bin
    zcat day16265.gz | perl -pe '$_ = pack "q>", (split /\s+/)[1]' > day16265.tv2nspid.bin
    ...

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

    G                 Global hash with all the results

The following instructions have had their action slightly amended:

    BPF_LD+BPF_ABS    A <- C[k]
    BPF_LD+BPF_IND    A <- C[X + k]

    BPF_RET           Non-zero adds/replaces R[] in G

**N.B.** all operations are as 64bit signed integer math

The following load/store/find `BPF_REC` (record) instructions have been added:

    BPF_LD+BPF_REC    A <- R[k]
    BPF_ST+BPF_REC    R[k] <- A

    BPF_MISC+BPF_LDR  Fetch R[] from G

# TODO

In roughly order of importance:

 * tool to generate mock data to experiment with
 * remove `HACK` and make everything more dynamic
 * improve the profiling support
 * add stepping debugging support
 * frequency analysis
 * Venn statements
 * SQL to BPF converter
 * BPF optimiser
 * [`posix_madvise()`](http://www.freebsd.org/cgi/man.cgi?posix_madvise(2)) hints
 * investigate [Blosc](http://www.blosc.org/) and its [c-blosc](https://github.com/Blosc/c-blosc) library
