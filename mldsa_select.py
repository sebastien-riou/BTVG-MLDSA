import sys
import os
import hdrbg 
import hashlib
import copy
import logging
from pysatl import Utils

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

#find a set of data inputs which include:
#- min repetition number (1)
#- max repetition number (from the captured cases)
#- has average matching theoritical average (i.e. 3.85 for ML-DSA-87)

def select_testvectors(data,*,only1 = False, check_flare = False,dst_dir=None):
    match(data['mldsa pset']):
        case 44:
            target_average = 4.25
        case 65:
            target_average = 5.1
        case 87:
            target_average = 3.85
        case _:
            raise RuntimeError()

    entropy = data['hdrbg seed']+bytes(24)
    logging.debug(f'entropy: {Utils.hexstr(entropy)}')
    drbg = hdrbg.DRBG_SHA2_256(entropy=entropy,nonce=bytes(32))
    drbg_msg = copy.deepcopy(drbg)
    dut = get_mldsa_impl(paramset=data['mldsa pset'])
    zeta = bytearray()
    zeta += drbg.get_bytes(32)
    #print(Utils.hexstr(zeta))

    pk, sk = dut.key_derive(seed=zeta)
    logging.debug(f'private key = {Utils.hexstr(sk)}')
    logging.debug(f'private key = {Utils.hexstr(pk)}')
    if pk != data['pk']:
        raise RuntimeError('pk does not match')
    if sk != data['sk']:
        raise RuntimeError('sk does not match')
    if data['ctx size'] > 0:
        raise NotImplementedError()
    message_size=data['msg size']
    message = bytearray(message_size)

    def index_to_data(idx):
        drbg_msg_tmp = copy.deepcopy(drbg_msg)
        message[0:8] = drbg_msg_tmp.get_bytes(8,additional_input=idx.to_bytes(8,byteorder='little')) 

        sig = dut.sign(sk=sk,m=message,ctx=bytes(0),deterministic=True)
        logging.debug(f'{idx:5} {dut.nr_sign_iterations:3} {dut.check_z_fail:2} {dut.check_r_fail:2} {dut.check_t0_fail:2} {dut.check_h_fail:2} {Utils.hexstr(message[0:8])}')
        return {'sig':sig, 'repetitions':dut.nr_sign_iterations}
        
    if (len(data['repetitions'])<300 and not only1):
        # we have only one test vector, generate additional test vectors
        for i in range(0,300):
            idx_data = index_to_data(i)
            data['iterations'].append(i)
            data['repetitions'].append(idx_data['repetitions'])

    max_loops = max(data['repetitions'])
    min_loops = min(data['repetitions'])

    print(f'{len(data['repetitions'])} signatures: repetitions between {min_loops} and {max_loops} included')

    if min_loops > 1:
        raise RuntimeError("the data set does not contain the minimal number of repetition")

    src = dict(zip(data['iterations'],data['repetitions']))
    logging.debug(src)

    selected = dict()
    selected_sum = 0
    selected_ave = 0
    too_low = False
    too_high = False

    def take_at(index):
        nonlocal selected_ave, selected_sum, selected, src, too_low, too_high
        v = src.pop(index)
        selected[index] = v
        selected_sum += v 
        selected_ave = selected_sum / len(selected)
        threshold = 0.0001
        too_low = False
        too_high = False
        if selected_ave >= target_average+threshold:
            too_high = True
        if selected_ave <= target_average-threshold:
            too_low = True

    def key_for(value):
        return list(src.keys())[list(src.values()).index(value)]

    take_at(key_for(1))

    if not only1:
        take_at(key_for(max_loops))
        def selection():
            while too_low or too_high:
                index = None
                ideal = (len(selected)+1) * target_average - selected_sum
                if ideal<1:
                    ideal = 1
                if too_low:
                    for k,v in src.items():
                        if v >= ideal and v < 2*ideal:
                            index = k
                            break
                    for k,v in src.items():
                        if v >= ideal:
                            index = k
                            break
                    for k,v in src.items():
                        if v >= target_average:
                            index = k
                            break
                else:
                    for k,v in src.items():
                        if v <= ideal:
                            index = k
                            break
                    for k,v in src.items():
                        if v <= target_average:
                            index = k
                            break
                if index is None:
                    raise RuntimeError('Target average not achievable')
                #print(ideal, v)
                take_at(index)

        selection()

    print(len(selected))
    logging.debug(str(selected))
    print(f'average = {selected_ave}')

    indexes = list(selected.keys())
    indexes.sort()
    logging.debug(str(indexes))

    i=0
    tv=0
    sigs = bytearray()
    repetitions_sum = 0
    repetitions_min = 814
    repetitions_max = 0
    repetitions = []
    for idx in indexes:
        idx_data = index_to_data(idx)
        sigs += idx_data['sig']
        repetitions.append(idx_data['repetitions'])
        repetitions_sum += idx_data['repetitions']
        repetitions_min = min(repetitions_min,idx_data['repetitions'])
        repetitions_max = max(repetitions_max,idx_data['repetitions'])
        tv += 1

    if repetitions_min != 1:
        raise RuntimeError(f'repetition_min = {repetitions_min}, 1 expected')

    if repetitions_max != max_loops:
        raise RuntimeError(f'repetition_max = {repetitions_max}, {max_loops} expected')

    if not only1:
        repetitions_ave = repetitions_sum/len(indexes)
        if selected_ave != repetitions_ave:
            raise RuntimeError(f'repetitions_ave = {repetitions_ave}, {selected_ave} expected')

    digest = hashlib.sha256(sigs).digest()
    base_name = f"mldsa{data['mldsa pset']}-m{gen_mldsa_inputs.size_str(data['msg size'])}-h{Utils.hexstr(digest[:4],separator='')}"
    if dst_dir:
        base_name = os.path.join(dst_dir,base_name)
    out_file = base_name+'.sel.py'
    with open(out_file,'w') as f:
        def p(s):
            print(s,file=f)
        p(f'hdrbg_seed = {data['hdrbg seed']}')
        p(f'mldsa_seed = {data['mldsa seed']}')
        p(f'sk = {data['sk']}')
        p(f'pk = {data['pk']}')
        p(f'mldsa_pset = {data['mldsa pset']}')
        p(f'ctx_size = {data['ctx size']}')
        p(f'msg_size = {data['msg size']}')
        p(f'indexes = {indexes}')
        p(f'repetitions = {repetitions}')
        p(f'average = {selected_ave}')
        p(f'max_repetitions = {max_loops}')
        p(f'sigs_sha256_digest = {digest}')
    return out_file

if __name__ == '__main__':
    import parse_aborts
    data = parse_aborts.parse_aborts(sys.argv[1])
    select_testvectors(data)