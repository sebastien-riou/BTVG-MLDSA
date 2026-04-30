import hdrbg
import runpy
import os,sys
from pysatl import Utils
import hashlib
import argparse
import logging
import io
import copy


from mldsa_utils import gen_mldsa_outputs, size_str

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