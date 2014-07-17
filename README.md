

# Sample

Lets get a tab seperated TIM,TV2NSPID sample:

    psp-read /psp-data/day16265/psval{TIM,TV2NSPID}.psp | pigz -c > day16265.tim.tv2nspid.gz

Break out each field and convert it to network ordered (big-endian) 64bit signed values:

    # network order
    zcat day16265.tim.tv2nspid.gz | perl -pe '$_ = pack "q>", (split /\s+/)[0]' | pigz -c > day16265.tim.bin.gz
    zcat day16265.tim.tv2nspid.gz | perl -pe '$_ = pack "q>", (split /\s+/)[1]' | pigz -c > day16265.tv2nspid.bin.gz
