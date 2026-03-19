# This generate simple python file declaring a single dict 'MLDSA_KATs'
# Invoke like this: pipenv run python gen_python_dict.py 69 ~/Downloads/mldsa-p37-m108-r96-1-1-119-1-1-86-1-1/ 
import runpy
import hashlib
from gen_mldsa_inputs import gen_mldsa_inputs
from mldsa_select import get_mldsa_impl
from dilithium_py.src.dilithium_py.ml_dsa.default_parameters import ML_DSA_44

import sys
import os
import glob

mlen = sys.argv[1]
base_dir = sys.argv[2]

with open(os.path.join(base_dir,f'mldsa-m{mlen}-as-dict.py'),'w') as f:
    MLDSA_KATs = {}
    print(f'# MLDSA test vectors for message length = {mlen}, context length = 0',file=f)
    print(f'# Generated from the following files:',file=f)

    pattern = os.path.join(base_dir,f'mldsa*-m{mlen}-*.sel.py')
    print('search pattern:',pattern)
    sel_files = glob.glob(pattern)
    for sel in sel_files:
        print(f'Processing {sel}')
        print(f'# \t{os.path.basename(sel)}',file=f)
        # Get the parameters
        params = runpy.run_path(sel) 
        pset = params['mldsa_pset']
        impl = get_mldsa_impl(pset)

        # Generate the inputs
        messages, mprimes, mus = gen_mldsa_inputs(params)
        sigs = bytearray()

        pk, sk = impl.key_derive(seed=params['mldsa_seed'])

        # Process the inputs, here for pure ML-DSA.Sign
        for message in messages:
            sig = impl.sign(sk=sk,m=message,ctx=bytes(0),deterministic=True) # TODO: Replace this with your implementation
            sigs += sig

        # verify digest over signatures
        digest = hashlib.sha256(sigs).digest()
        if digest == params['sigs_sha256_digest']:
            print('all test vectors executed correctly')
        else:
            raise RuntimeError()
        out = {}
        out['keygen_seed'] = bytes(params['mldsa_seed'])
        out['pk'] = bytes(pk)
        out['sk'] = bytes(sk)
        out['perf_messages'] = messages
        MLDSA_KATs[f'MLDSA_{pset}'] = out
        MLDSA_KATs['sign_seed'] = bytes(32) #MLDSA deterministic mode

    
    print(f'MLDSA_KATs = {MLDSA_KATs}',file=f)