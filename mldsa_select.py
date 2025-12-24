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

#find a set of data inputs which include:
#- min repetition number (1)
#- max repetition number (from the captured cases)
#- has average matching theoritical average (i.e. 3.85 for ML-DSA-87)

def select_testvectors(data,*,only1 = False, dst_dir=None):
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

    best_case = None
    if not only1:
        #identify a best case
        logging.info(f"Check that best case for mldsa{data['mldsa pset']} is present in data set")
        best_case = None
        start=0
        while True:
            try:
                idx = data['repetitions'].index(1,start)
            except ValueError:
                break
            iteration = data['iterations'][idx]
            idx_data = index_to_data(iteration)
            if dut.tau == idx_data['sib_bytes']:
                best_case = iteration
                logging.info(f"Best case for mldsa{data['mldsa pset']} is present in data set")
                # move it as first data to ensure it is included
                data['iterations'].insert(0, data['iterations'].pop(idx))
                data['repetitions'].insert(0, data['repetitions'].pop(idx))
                break
            start = idx + 1
        
        if best_case is None:
            # search best case
            logging.info(f"Best case for mldsa{data['mldsa pset']} is NOT present in data set")
            logging.info(f"Search for best case for mldsa{data['mldsa pset']}")
            iteration = max(data['iterations']) + 1
            while True:
                idx_data = index_to_data(iteration)
                if (1 == idx_data['repetitions']) and (dut.tau == idx_data['sib_bytes']):
                    best_case = iteration
                    # insert the best case as first data to ensure it is included
                    data['iterations'].insert(0,iteration)
                    data['repetitions'].insert(0,idx_data['repetitions'])
                    logging.info(f"Best case for mldsa{data['mldsa pset']} added to data set")
                    break
                iteration += 1

    max_loops = max(data['repetitions'])
    min_loops = min(data['repetitions'])

    logging.info(f'{len(data['repetitions'])} signatures: repetitions between {min_loops} and {max_loops} included')

    if min_loops > 1:
        raise RuntimeError("the data set does not contain the minimal number of repetition")
    if not only1:
        logging.info(f"Best case for mldsa{data['mldsa pset']} at iteration {best_case}")

    src = dict(zip(data['iterations'],data['repetitions']))
    def key_for(value, *,start=0):
        """find key associated with value in scr"""
        return list(src.keys())[list(src.values()).index(value, start)]

    logging.debug(src)
    logging.debug(f'{len(src)} cases in data set')

    selected = dict()
    selected_sum = 0
    selected_ave = 0
    too_low = False
    too_high = False

    def take_at(index):
        nonlocal selected_ave, selected_sum, selected, src, too_low, too_high
        v = src.pop(index)
        if index in selected:
            raise RuntimeError()
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
        logging.debug(f'{len(selected)}, sum={selected_sum}, ave={selected_ave}')

    last_iteration = max(data['iterations'])
    def add_specific_repetition(target: int):
        nonlocal src, last_iteration
        logging.debug(f'Searching for repetitions = {target}')
        iteration = last_iteration + 1
        while True:
            idx_data = index_to_data(iteration)
            if target == idx_data['repetitions']:
                src[iteration] = idx_data['repetitions']
                break
            iteration += 1
        last_iteration = iteration
        logging.debug(f'Adding iteration = {iteration}, repetition = {src[iteration]}')
        return iteration

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
                        if v >= ideal and v < ideal+1:
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
                    #generate the ideal value
                    if too_low:
                        v = math.ceil(ideal)
                    else:
                        v = math.floor(ideal)
                    index = add_specific_repetition(v)
                    #logging.error(f"selected: {selected}")
                    #logging.error(f"left in src: {src}")
                    #raise RuntimeError('Target average not achievable')
                
                take_at(index)
                logging.debug(f'ideal={ideal}, actual={v}')
                

        selection()

    logging.info(f"Number of selected messages: {len(selected)}")
    logging.debug(str(selected))
    logging.info(f'Average repetitions = {selected_ave}')

    indexes = list(selected.keys())
    indexes.sort()
    logging.debug(str(indexes))
    logging.debug(f"Number of selected messages: {len(indexes)}")
    

    i=0
    tv=0
    sigs = bytearray()
    repetitions_sum = 0
    repetitions_min = 814
    repetitions_max = 0
    repetitions = []
    sib_bytes = []
    best_case = None
    for idx in indexes:
        idx_data = index_to_data(idx)
        sigs += idx_data['sig']
        rep = idx_data['repetitions']
        repetitions.append(rep)
        sib_bytes.append(idx_data['sib_bytes'])
        if 1 == idx_data['repetitions']:
            if dut.tau == idx_data['sib_bytes']:
                best_case = idx
        repetitions_sum += rep
        repetitions_min = min(repetitions_min,rep)
        repetitions_max = max(repetitions_max,rep)
        tv += 1
        logging.debug(f'{tv}, {idx}, {rep} added: sum = {repetitions_sum}, ave = {repetitions_sum/tv}')

    if repetitions_min != 1:
        raise RuntimeError(f'repetition_min = {repetitions_min}, 1 expected')

    if repetitions_max != max_loops:
        raise RuntimeError(f'repetition_max = {repetitions_max}, {max_loops} expected')

    if not only1:
        repetitions_ave = repetitions_sum/len(indexes)
        if selected_ave != repetitions_ave:
            raise RuntimeError(f'repetitions_ave = {repetitions_ave}, {selected_ave} expected')
        if best_case is None:
            raise RuntimeError(f'Best case not in the selection')

    digest = hashlib.sha256(sigs).digest()
    base_name = f"mldsa{data['mldsa pset']}-m{gen_mldsa_inputs.size_str(data['msg size'])}-h{Utils.hexstr(digest[:4],separator='')}"
    if dst_dir:
        base_name = os.path.join(dst_dir,base_name)
    out_file = base_name+'.sel.py'
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
    params['average'] = selected_ave
    params['max_repetitions'] = max_loops
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

if __name__ == '__main__':
    import parse_aborts
    data = parse_aborts.parse_aborts(sys.argv[1])
    select_testvectors(data)