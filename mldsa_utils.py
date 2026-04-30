import hdrbg
import runpy
import os,sys
from pysatl import Utils
import hashlib
import argparse
import logging
import io
import copy
import json

from dilithium_py.src.dilithium_py.ml_dsa import default_parameters

def size_str(size):
    for u in [['G',1024*1024*1024],['M',1024*1024],['K',1024]]:
        divider = u[1]
        if 0 == size % divider:
            return f'{size // divider}{u[0]}'
    return f'{size}'

def get_mldsa_impl(paramset:int):
    match(paramset):
        case 44:
            return default_parameters.ML_DSA_44
        case 65:
            return default_parameters.ML_DSA_65
        case 87:
            return default_parameters.ML_DSA_87
        case _:
            raise NotImplementedError(f'Unsupported parameter set {paramset}')

# A functions to generate all inputs from the parameters
def gen_mldsa_inputs(params):
    if params['ctx_size'] > 0:
        raise RuntimeError('Not implemented')

    msg_size = params['msg_size']

    #seed DRBG
    drbg = hdrbg.DRBG_SHA2_256(entropy=params['hdrbg_seed']+bytes(24),nonce=bytes(32))
    drbg_msg = copy.deepcopy(drbg)
    #take zeta out
    zeta = bytearray()
    zeta += drbg.get_bytes(32)
    impl = get_mldsa_impl(params['mldsa_pset'])
    pk, sk = impl.key_derive(seed=zeta)

    #generate initial message
    message = bytearray(msg_size)

    indexes = params['indexes']
    message_size = params['msg_size']
    messages = []
    for idx in indexes:
        drbg_msg_tmp = copy.deepcopy(drbg_msg)
        hbound = min(8,message_size)
        message[0:hbound] = drbg_msg_tmp.get_bytes(hbound,additional_input=idx.to_bytes(8,byteorder='little')) 
        messages.append(bytes(message))

    # Compute M' for Sign_Internal
    mprimes = []
    for i in range(0,len(messages)):
        m = bytearray()
        m += bytes(2) #assume ctx_size=0
        m += messages[i]
        mprimes.append(bytes(m))

    # Compute Mu
    mus = []
    tr = params['sk'][64:128]
    for i in range(0,len(messages)):
        m = bytearray(tr)
        m += mprimes[i]
        mus.append(hashlib.shake_256(m).digest(64))

    return messages, mprimes, mus, pk, sk

# A functions to generate all inputs from the parameters
def gen_mldsa_outputs(params):
    messages, _mprimes, _mus, _pk, sk = gen_mldsa_inputs(params)
    impl = get_mldsa_impl(params['mldsa_pset'])
    #entropy = params['hdrbg_seed']+bytes(24)
    #logging.debug(f'entropy: {Utils.hexstr(entropy)}')
    #drbg = hdrbg.DRBG_SHA2_256(entropy=entropy,nonce=bytes(32))
    #zeta = bytearray()
    #zeta += drbg.get_bytes(32)
    #_pk, sk = impl.key_derive(seed=zeta)
    signatures = []
    for m in messages:
        signatures.append(impl.sign(sk=sk,m=m,ctx=bytes(0),deterministic=True))
    return signatures

def gen_tv_name(params):
    base_name = f"mldsa{params['mldsa_pset']}-m{size_str(params['msg_size'])}-h{Utils.hexstr(params['sigs_sha256_digest'][:4],separator='')}"
    return base_name

if __name__ == '__main__':
    scriptname = os.path.basename(__file__)
    scriptpath = os.path.dirname(__file__)
    parser = argparse.ArgumentParser(scriptname)
    levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    parser.add_argument('--log-level', default='INFO', choices=levels)
    parser.add_argument('params', default=None, help='Path to input parameter file (.py)', type=str)
    formats = ('C', 'ACVP', 'SV', 'ALL')
    parser.add_argument('format', default='ACVP', choices=formats, help='output format')
    parser.add_argument('--expand-msg', help='Fully expand message input', action='store_true')
    parser.add_argument('--write', default='', help='Path to write result files', type=str)

    args = parser.parse_args()
    logformat = '%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s'
    logdatefmt = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(level=args.log_level, format=logformat, datefmt=logdatefmt)

    gen_c=False
    gen_sv=False
    match args.format:
        case 'C':
            gen_c = True
        case 'SV':
            gen_sv = True
        case 'ALL':
            gen_c = True
            gen_sv = True

    # Get the parameters
    params = runpy.run_path(args.params)
    
    out=[]
    if gen_c:
        out.append(['c',format_as_c(params,expand_msg=args.expand_msg)])
    if gen_sv:
        out.append(['sv',format_as_sv(params,expand_msg=args.expand_msg)])
    

    #base_name = f"mldsa{params['mldsa_pset']}-m{size_str(params['msg_size'])}-h{Utils.hexstr(params['sigs_sha256_digest'][:4],separator='')}"
    base_name = gen_tv_name(params)
    base_name = os.path.join(args.write,base_name)
    for o in out:
        with open(base_name+'.'+o[0],'w') as f:
            print(o[1],file=f)
