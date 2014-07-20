Some experiments in grafting [BPF](http://en.wikipedia.org/wiki/Berkeley_Packet_Filter) onto a [Column-oriented DBMS](http://en.wikipedia.org/wiki/Column-oriented_DBMS) and providing an SQL like interface to the user.

# Preflight

    sudo apt-get install build-essential uthash-dev
    
    git clone https://github.com/jimdigriz/bpf-sql.git
    cd bpf-sql
    make

## Dry-Run

Lets get a tab seperated TIM,TV2NSPID sample:

    psp-read /psp-data/day16265/psval{TIM,TV2NSPID}.psp | pigz -c > day16265.tim.tv2nspid.gz

Break out each field and convert it to network ordered (big-endian) 64bit signed values:

    # network order
    zcat day16265.tim.tv2nspid.gz | perl -pe '$_ = pack "q>", (split /\s+/)[0]' | pigz -c > day16265.tim.bin.gz
    zcat day16265.tim.tv2nspid.gz | perl -pe '$_ = pack "q>", (split /\s+/)[1]' | pigz -c > day16265.tv2nspid.bin.gz

# Engine

The engine closely resembles the BPF filtering engine described in the [BSD BPF manpage](http://www.freebsd.org/cgi/man.cgi?bpf(4)) which is closely modelled after the [Steven McCanne's and Van Jacobson's BPF paper](http://usenix.org/publications/library/proceedings/sd93/mccanne.pdf).

    Element          Description
    
    A                64 bit wide accumulator
    X                64 bit wide X register
    M[]              BPF_MEMWORDS x 64 bit wide misc registers aka "scratch
                     memory store", addressable from 0 BPF_MEMWORDS-1
    
    C[]              NCOL x 64bit wide read-only column registers that
                     have the current row record data (akin to BPF's P[])
    R[]              RCOL x 64bit wide registers to create/replace records

Addition of a new load/store destination `BPF_REC` (record) that provides:

    BPF_LD+BPF_REC   A <- R[k]
    BPF_LDX+BPF_REC  X <- R[k]
    
    BPF_ST+BPF_REC   R[k] <- A
    BPF_STX+BPF_REC  R[k] <- X
