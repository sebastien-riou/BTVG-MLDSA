# Invoke like this: pipenv run python example.py 
import runpy
import hashlib
from gen_mldsa_inputs import gen_mldsa_inputs
from dilithium_py.src.dilithium_py.ml_dsa.default_parameters import ML_DSA_44

# Get the parameters
params = runpy.run_path('results/mldsa44-m69-h12FA23B2.sel.py') # TODO: Replace the file by the real test vector

# Generate the inputs
messages, mprimes, mus = gen_mldsa_inputs(params)
sigs = bytearray()

pk, sk = ML_DSA_44.key_derive(seed=params['mldsa_seed'])

# Process the inputs, here for pure ML-DSA.Sign
for message in messages:
    sig = ML_DSA_44.sign(sk=sk,m=message,ctx=bytes(0),deterministic=True) # TODO: Replace this with your implementation
    sigs += sig

# verify digest over signatures
digest = hashlib.sha256(sigs).digest()
if digest == params['sigs_sha256_digest']:
    print('all test vectors executed correctly')
else:
    raise RuntimeError()