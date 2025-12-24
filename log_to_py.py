import sys
import os
import hdrbg 
import hashlib
import copy
import logging
import io
from pysatl import Utils
import math

import gen_mldsa_inputs
from dilithium_py.src.dilithium_py.ml_dsa import default_parameters


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

def data_to_py(data,*, dst_dir=None):
    entropy = data['hdrbg seed']+bytes(24)
    logging.debug(f'entropy: {Utils.hexstr(entropy)}')
    drbg = hdrbg.DRBG_SHA2_256(entropy=entropy,nonce=bytes(32))
    drbg_msg = copy.deepcopy(drbg)
    dut = get_mldsa_impl(paramset=data['mldsa pset'])
    zeta = bytearray()
    zeta += drbg.get_bytes(32)
    logging.debug(f'zeta = {Utils.hexstr(zeta)}')

    pk, sk = dut.key_derive(seed=zeta)
    logging.debug(f'private key = {Utils.hexstr(sk)}')
    logging.debug(f'public key = {Utils.hexstr(pk)}')
    if pk != data['pk']:
        if len(pk) != len(data['pk']):
            raise RuntimeError(f"pk length does not match: {len(pk)} vs {len(data['pk'])}")
        for i in range(0,len(pk)):
            if pk[i] != data['pk'][i]:
                raise RuntimeError(f"pk does not match at index {i} ({pk[i]:#02x} vs {data['pk'][i]:#02x})!")
        raise RuntimeError('pk does not match somehow!')
    if sk != data['sk']:
        raise RuntimeError('sk does not match')
    if data['ctx size'] > 0:
        raise NotImplementedError()
    message_size=data['msg size']
    message = bytearray(message_size)

    def index_to_data(idx):
        drbg_msg_tmp = copy.deepcopy(drbg_msg)
        hbound = min(8,message_size)
        message[0:hbound] = drbg_msg_tmp.get_bytes(hbound,additional_input=idx.to_bytes(8,byteorder='little')) 

        sig = dut.sign(sk=sk,m=message,ctx=bytes(0),deterministic=True)
        logging.debug(f'{idx:5} {dut.nr_sign_iterations:3} {dut.check_z_fail:2} {dut.check_r_fail:2} {dut.check_t0_fail:2} {dut.check_h_fail:2} sip:{dut.sib_bytes_cnt:2} - {Utils.hexstr(message[0:8])}')
        return {'sig':sig, 'repetitions':dut.nr_sign_iterations, 'sib_bytes':dut.sib_bytes_cnt}

    indexes = data['iterations']
    i=0
    tv=0
    sigs = bytearray()
    repetitions_sum = 0
    repetitions_min = 814
    repetitions_max = 0
    repetitions = []
    sib_bytes = []
    for idx in indexes:
        idx_data = index_to_data(idx)
        sigs += idx_data['sig']
        rep = idx_data['repetitions']
        repetitions.append(rep)
        sib_bytes.append(idx_data['sib_bytes'])
        repetitions_sum += rep
        repetitions_min = min(repetitions_min,rep)
        repetitions_max = max(repetitions_max,rep)
        tv += 1
        logging.debug(f'{tv}, {idx}, {rep} added: sum = {repetitions_sum}, ave = {repetitions_sum/tv}')

    digest = hashlib.sha256(sigs).digest()
    base_name = f"mldsa{data['mldsa pset']}-m{gen_mldsa_inputs.size_str(data['msg size'])}-h{Utils.hexstr(digest[:4],separator='')}"
    print(f'dst_dir={dst_dir}')
    if dst_dir:
        base_name = os.path.join(dst_dir,base_name)
    out_file = base_name+'.py'
    params = {}
    params['hdrbg_seed'] = data['hdrbg seed']
    params['mldsa_seed'] = data['mldsa seed']
    params['sk'] = data['sk']
    params['pk'] = data['pk']
    params['mldsa_pset'] = data['mldsa pset']
    params['ctx_size'] = data['ctx size']
    params['msg_size'] = data['msg size']
    params['indexes'] = indexes
    params['repetitions'] = repetitions
    params['average'] = repetitions_sum/tv
    params['max_repetitions'] = repetitions_max
    params['sigs_sha256_digest'] = digest
    params['sib_bytes'] = sib_bytes
    write_params(out_file,params)
    return out_file

def params_to_str(params):
    out = io.StringIO()
    def p(s):
        print(s,file=out)
    p(f'hdrbg_seed = {params['hdrbg_seed']}')
    p(f'mldsa_seed = {params['mldsa_seed']}')
    p(f'sk = {params['sk']}')
    p(f'pk = {params['pk']}')
    p(f'mldsa_pset = {params['mldsa_pset']}')
    p(f'ctx_size = {params['ctx_size']}')
    p(f'msg_size = {params['msg_size']}')
    p(f'indexes = {params['indexes']}')
    p(f'repetitions = {params['repetitions']}')
    p(f'average = {params['average']}')
    p(f'max_repetitions = {params['max_repetitions']}')
    p(f'sigs_sha256_digest = {params['sigs_sha256_digest']}')
    p(f'sib_bytes = {params['sib_bytes']}')
    return out.getvalue()

def write_params(dst,params):
    with open(dst,'w') as f:
        print(params_to_str(params),file=f)

def log_to_py(src_path,*, dst_dir=None):
    import parse_aborts
    data = parse_aborts.parse_aborts(src_path)
    print(f'dst_dir={dst_dir}')
    data_to_py(data, dst_dir=dst_dir)

if __name__ == '__main__':
    dst_dir = None
    if len(sys.argv)>2:
        dst_dir = sys.argv[2]
        print(f'dst_dir={dst_dir}')
    log_to_py(sys.argv[1],dst_dir=dst_dir)
