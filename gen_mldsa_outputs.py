import hdrbg
import runpy
import os,sys
from pysatl import Utils
import hashlib
import argparse
import logging
import io
import copy


from gen_mldsa_inputs import gen_mldsa_inputs,size_str
from mldsa_select import get_mldsa_impl

# A functions to generate all inputs from the parameters
def gen_mldsa_outputs(params):
    messages, _mprimes, _mus = gen_mldsa_inputs(params)
    impl = get_mldsa_impl(params['mldsa_pset'])
    entropy = params['hdrbg_seed']+bytes(24)
    logging.debug(f'entropy: {Utils.hexstr(entropy)}')
    drbg = hdrbg.DRBG_SHA2_256(entropy=entropy,nonce=bytes(32))
    zeta = bytearray()
    zeta += drbg.get_bytes(32)
    _pk, sk = impl.key_derive(seed=zeta)
    signatures = []
    for m in messages:
        signatures.append(impl.sign(sk=sk,m=m,ctx=bytes(0),deterministic=True))
    return signatures

if __name__ == '__main__':
    scriptname = os.path.basename(__file__)
    scriptpath = os.path.dirname(__file__)
    parser = argparse.ArgumentParser(scriptname)
    levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    parser.add_argument('--log-level', default='INFO', choices=levels)
    parser.add_argument('params', default=None, help='Path to input parameter file (.py)', type=str)
    parser.add_argument('--write', help='Write output to file(s)', action='store_true')

    args = parser.parse_args()
    logformat = '%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s'
    logdatefmt = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(level=args.log_level, format=logformat, datefmt=logdatefmt)

    # Get the parameters
    params = runpy.run_path(args.params)
    sigs = gen_mldsa_outputs(params)
    if args.write:
        base_name = f"mldsa{params['mldsa_pset']}-m{size_str(params['msg_size'])}-h{Utils.hexstr(params['sigs_sha256_digest'][:4],separator='')}"
        with open(base_name+'-sigs.txt','w') as f:
            for sig in sigs:
                print(Utils.hexstr(sig),file=f)
    else:
        for sig in sigs:
            print(Utils.hexstr(sig,head='0x',separator=', '))