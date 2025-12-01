# BTVG-MLDSA
Benchmarking Test Vectors Generator for MLDSA sign

## How to build
`./init` is doing the following:
- initialize the git sub-modules (instrumented forks of mldsa-native and dilithium-py)
- build the C program `mldsa-tv-gen`
- initialize a Python virtual environment using `pipenv`

## How to generate the test vectors

### the easy way
This generate test vectors using a single process, so this is limited to development and quick demos.

1. use `log_aborts_all_cases` script to generate candidate test vectors for all ML-DSA key sizes and all message sizes, i.e., `./log_aborts_all_cases 00 --n-trials=10K`
2. use `mldsa-sign-tvgen.py` script to generate the test vectors, i.e. `pipenv run python mldsa-sign-tvgen.py --read-log results/`


### the long way
This generate test vectors using as many process in parallel as you want, but search for a single ML-DSA key size at a time.

1. use `search` script to find a high repetition count case, i.e. `./search 44 30 1M 00 2`
2. wait all processes `mldsa-tv-gen` terminate
3. use `log_aborts_long_msg_sizes` script to find single repetition cases for long messages, i.e. `./log_aborts_long_msg_sizes 44 00`
4. repeat 1 and 2 for ML-DSA-65 and ML-DSA-87
5. use `mldsa-sign-tvgen.py` script to generate the test vectors, i.e. `pipenv run python mldsa-sign-tvgen.py --read-log results/`

NOTE: 
In this example, we inkoked the `search` script with 30 for min-repetitions on 2 processes, each of them with 1 million trials.
If you set higher number of processes and/or higher number of trials, you may want to set a higher min-repetition to limit the 
size of log files.

## How to use the test vectors

### Python
See `example.py`

### C

````
#include <stdint.h>
#include "results/mldsa44-m69-h30D1C064.c"

void gen_message(unsigned int index, uint8_t*dst, size_t dst_size){
TODO
}
````

### System verilog

````
TODO
````
