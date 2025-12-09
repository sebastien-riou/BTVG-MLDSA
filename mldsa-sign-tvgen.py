import argparse
import copy
import logging
import os
import runpy
import hdrbg
import math 

from pysatl import Utils

import parse_aborts
import mldsa_select
import gen_mldsa_inputs

def pset_to_average_repetitions(pset:int):
    match(pset):
        case 44:
            target_average = 4.25
        case 65:
            target_average = 5.1
        case 87:
            target_average = 3.85
        case _:
            raise RuntimeError()
    return target_average

def repetitions_to_prob_power(pset: int, repetitions: int, floor=True):
    ave = pset_to_average_repetitions(pset)
    base = (ave-1)/ave
    prob_power = -math.log(base**repetitions) / math.log(2)
    if floor:
        return math.floor(prob_power)
    else:
        return prob_power

def prob_power_to_repetitions(pset: int, prob_power: int, ceil=True):
    ave = pset_to_average_repetitions(pset)
    base = (ave-1)/ave
    repetitions = math.log(2**-prob_power)/math.log(base)
    if ceil:
        return math.ceil(repetitions)
    else:
        return repetitions

if __name__ == '__main__':
    scriptname = os.path.basename(__file__)
    scriptpath = os.path.dirname(__file__)
    parser = argparse.ArgumentParser(scriptname)
    levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    parser.add_argument('--log-level', default='WARNING', choices=levels)
    psets = ('44', '65', '87')
    #parser.add_argument('--param-set', default=None, help='ML-DSA parameter set', choices=psets)
    #parser.add_argument('--msg-size', default=69, help='Message size', type=int)
    #parser.add_argument('--seed', default=None, help='Seed for the tool DRBG', type=int)
    parser.add_argument('--search', default=None, help='Path to result log files to search for high repetition cases (.log)', type=str)
    parser.add_argument('--read-log', default=None, help='Path to result log files already generated (.log)', type=str)
    parser.add_argument('--read-sel', default=None, help='Path to result selection files already generated (.sel.py)', type=str)
    parser.add_argument('--write', default=None, help='Path to write result files', type=str)
    parser.add_argument('--remove-empty', default=False, help='Remove files with no results', type=bool)
    
    args = parser.parse_args()
    logformat = '%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s'
    logdatefmt = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(level=args.log_level, format=logformat, datefmt=logdatefmt)
    #logging.getLogger('hdrbg').setLevel(logging.INFO)
    def set_other_loggers_level(level):
        for log_name, log_obj in logging.Logger.manager.loggerDict.items():
            if log_name != __name__:
                #log_obj.disabled = True
                logging.getLogger(log_name).setLevel(level)
    set_other_loggers_level(logging.INFO)

    if not args.read_log and not args.read_sel and not args.search:
        raise RuntimeError('one of --read-log or --read-sel or --search is mandatory for now')
    
    read_log = args.read_log
    if args.search:
        read_log = args.search

    sel_files = []
    selection_dir = None
    if args.read_sel:
        selection_dir = args.read_sel
        sel_files = [os.path.join(selection_dir, f) for f in os.listdir(selection_dir) if f.startswith('mldsa') and f.endswith('.sel.py')]
        sel_files = [f for f in sel_files if os.path.isfile(f) ]

    if read_log:
        dst_dir = read_log
        if args.write:
            dst_dir = args.write

        results_dir = read_log
        result_files = [os.path.join(results_dir, f) for f in os.listdir(results_dir) if f.endswith('.log')]
        result_files = [f for f in result_files if os.path.isfile(f) ]
        best_data = {}
        best_data_dropped = {}
        prob_powers = {}
        print(f'Loading {len(result_files)} result files.')
        for f in result_files:
            logging.debug(f)
            data = parse_aborts.parse_aborts(f)
            if 0==len(data['records']):
                if(args.remove_empty):
                    logging.info(f'Removing empty file : {f}')
                    os.remove(f)
                else:
                    logging.warning(f'Empty file could be removed, see --remove-empty: {f}')
                continue
            
            data['file'] = f
            pset = data['mldsa pset']
            key = f"{pset}-{data['msg size']}"
            data['prob_powers']=[]

            max_repetitions = min(data['repetitions'])
            last_dropped = None
            for i in range(0,len(data['repetitions'])):
                r = data['repetitions'][i]
                prob_power = repetitions_to_prob_power(pset,r)
                data['prob_powers'].append(prob_power)
                if 69 == data['msg size']:
                    prob_power_data = {}
                    prob_power_data['iterations'] = [data['iterations'][i]]
                    prob_power_data['repetitions'] = [r]
                    prob_power_data['hdrbg seed'] = data['hdrbg seed']
                    prob_power_data['mldsa seed'] = data['mldsa seed']
                    prob_power_data['mldsa pset'] = pset
                    prob_power_data['pk'] = data['pk']
                    prob_power_data['sk'] = data['sk']
                    prob_power_data['file'] = f
                    
                    if prob_power not in prob_powers: 
                        prob_powers[prob_power] = {}
                    if key in prob_powers[prob_power]:
                        if prob_powers[prob_power][key]['repetitions'][0] < r:
                            logging.debug(f"Drop case {r} (p{prob_power}) from file {f}")
                            last_dropped = prob_power_data
                            continue #ignore this one as it has a higher repetition but same probability (due to rounding to integers)
                        else:
                            logging.debug(f"Drop case (2) {prob_powers[prob_power][key]['repetitions'][0]} (p{prob_power}) from file {prob_powers[prob_power][key]['file']}")
                            last_dropped = prob_powers[prob_power].pop(key)
                    prob_powers[prob_power][key] = prob_power_data
                max_repetitions = max(max_repetitions,r)

            real_max_repetitions = max(data['repetitions'])
            if real_max_repetitions != max_repetitions:
                if pset == 44 and real_max_repetitions > 100:
                    logging.debug(f"Real max repetition is {real_max_repetitions} but we keep the data for {max_repetitions} because it has same integer power probability")
                    logging.debug(f"Dropped data is in {last_dropped['file']}")
            index = data['repetitions'].index(max_repetitions)
            max_repetitions_iteration = data['iterations'][index]

            if key in best_data:
                best_max_repetitions = best_data[key]['max_repetitions']
                best_prob = repetitions_to_prob_power(pset, best_max_repetitions)
            else:
                best_max_repetitions = 0
                best_prob = -1
            max_prob = repetitions_to_prob_power(pset, max_repetitions)

            takeit = False
            if max_prob > best_prob:
                takeit = True
                if last_dropped and (last_dropped['repetitions'][0] > best_max_repetitions):
                    logging.debug(f'New best dropped 1 for {pset}: {last_dropped['repetitions'][0]} vs {best_max_repetitions}')
                    best_data_dropped[key] = copy.deepcopy(last_dropped)
                elif key in best_data_dropped:
                    logging.debug(f'Remove best dropped for {pset}')
                    best_data_dropped.pop(key)
            elif max_prob == best_prob:
                if max_repetitions < best_max_repetitions:
                    takeit = True
                    if key in best_data:
                        logging.debug(f'New best dropped 2 for {pset}')
                        best_data_dropped[key] = copy.deepcopy(best_data[key])

            if last_dropped:
                logging.debug(f"last_dropped: {last_dropped['repetitions'][0]}, takeit={takeit}, max_repetition={max_repetitions}, best_max_repetitions={best_max_repetitions}. {max_prob} vs {best_prob}")
            else:
                logging.debug(f"takeit={takeit}, max_repetition={max_repetitions}, best_max_repetitions={best_max_repetitions}. {max_prob} vs {best_prob}")

            if takeit:
                data['max_repetitions'] = max_repetitions
                data['max_repetitions_iteration'] = max_repetitions_iteration
                best_data[key] = data
            else:
                if key in best_data_dropped:
                    if best_data_dropped[key]['repetitions'][0] < last_dropped['repetitions'][0]:
                        logging.debug(f'New best dropped 3 for {pset}')
                        best_data_dropped[key] = copy.deepcopy(last_dropped)

        logging.debug(f"best_data keys:{sorted(best_data.keys())}")

        all_prob_powers = sorted(prob_powers.keys(),reverse=True)
        highest_common_prob_power = None
        for p in all_prob_powers:
            #print(prob_powers[p])
            if 3 == len(prob_powers[p]): #we want the same probability for the 3 ML-DSA key sizes
                highest_common_prob_power = p 
                logging.info(f"highest_common_prob_power = {highest_common_prob_power}:\n\t{prob_powers[p]['44-69']['file']}\n\t{prob_powers[p]['65-69']['file']}\n\t{prob_powers[p]['87-69']['file']}")
                break

        for key in sorted(best_data_dropped.keys()):
            data = best_data_dropped[key]
            pset = data['mldsa pset']
            repetitions = data['repetitions'][0]
            logging.info(f"ML-DSA-{pset}: dropped max repetitions case {repetitions} (p{repetitions_to_prob_power(pset, repetitions)}) from file {data['file']}")

        for pset in [44,65,87]:
            key = f"{pset}-69"
            pset_prob_powers = {}
            for p in prob_powers.keys():
                if key in prob_powers[p].keys():
                    pset_prob_powers[p] = {'file':prob_powers[p][key]['file'],'repetitions':prob_powers[p][key]['repetitions'][0]}
            max_p = max(list(pset_prob_powers.keys()))
            # Note: we don't use prob_power_to_repetitions(pset,max_p) because sometime when reporting integers the mapping is not unique (can be off by +/- 1)
            logging.info(f"ML-DSA-{pset} max repetition case {pset_prob_powers[max_p]['repetitions']} (p{max_p}): {pset_prob_powers[max_p]['file']}")

        if highest_common_prob_power is None:
            logging.warning(f'No common prob power found in the data set')
        else:
            logging.debug('Replacing best_data with the highest common prob power')
            for key in sorted(best_data.keys()):
                data = best_data[key]
                if 69 == data['msg size']:
                    prob_power_data = prob_powers[highest_common_prob_power][key]
                    if data['mldsa pset'] != prob_power_data['mldsa pset']:
                        raise RuntimeError()
                    max_repetitions = data['max_repetitions']
                    data={} #start fresh to avoid having anything inconsistent if new members are added over time
                    data['mldsa pset'] = prob_power_data['mldsa pset']
                    data['msg size'] = 69
                    data['ctx size'] = 0
                    data['iterations'] = prob_power_data['iterations']
                    data['repetitions'] = prob_power_data['repetitions']
                    data['hdrbg seed'] = prob_power_data['hdrbg seed']
                    data['mldsa seed'] = prob_power_data['mldsa seed']
                    data['pk'] = prob_power_data['pk']
                    data['sk'] = prob_power_data['sk']
                    data['file'] = prob_power_data['file']
                    data['max_repetitions_iteration'] = prob_power_data['iterations'][0]
                    common_prob_max_repetition = prob_power_data['repetitions'][0]
                    if max_repetitions > common_prob_max_repetition:
                        pset=data['mldsa pset']
                        logging.warning(f"Dropping ML-DSA-{pset} max repetition case {max_repetitions} (p{repetitions_to_prob_power(pset,max_repetitions)}) to {common_prob_max_repetition} to achieve common probability p{repetitions_to_prob_power(pset,common_prob_max_repetition)}")
                    data['max_repetitions'] = common_prob_max_repetition
                    best_data[key] = data

        for key,data in best_data.items():
            print(f'mldsa{data['mldsa pset']} - msg size = {gen_mldsa_inputs.size_str(data['msg size'])} - hdrbg seed = {Utils.hexstr(data['hdrbg seed'])} - iteration {data['max_repetitions_iteration']} - max repetitions = {data['max_repetitions']}')
            if args.search:
                print(f'file {data['file']}')
            else:
                only1 = data['msg size'] > 69
                sel_files.append(mldsa_select.select_testvectors(data,dst_dir=dst_dir, only1=only1))
        if args.search:
            exit()

    #load selection data base
    selections = []
    for f in sel_files:
        selections.append(runpy.run_path(f))

    #keep only best sel files based on max_repetitions and then number of messages
    best_sel = {}
    for data in selections:
        key = f"mldsa{data['mldsa_pset']}-m{gen_mldsa_inputs.size_str(data['msg_size'])}"
        if key in best_sel:
            best_max_repetitions = best_sel[key]['max_repetitions']
        else:
            best_max_repetitions = 0
        if data['max_repetitions'] > best_max_repetitions:
            best_sel[key] = data
        elif data['max_repetitions'] == best_max_repetitions:
            if len(data['indexes']) < len(best_sel[key]['indexes']):
                best_sel[key] = data

    print('best selections:')
    best_sel_power_probs = []
    for key,data in best_sel.items():
        if 69 == data['msg_size']:
            logging.debug(f"{data['mldsa_pset']}, {data['hdrbg_seed']}, {data['msg_size']}, {data['indexes']}, {data['repetitions']}, {data['max_repetitions']}")
            power_prob = repetitions_to_prob_power(data['mldsa_pset'],data['max_repetitions'])
            best_sel_power_probs.append(power_prob)
            print(f'{key}-h{Utils.hexstr(data['sigs_sha256_digest'][:4],separator='')}: max repetitions = {data['max_repetitions']}, probability power = {power_prob}, {len(data['indexes'])} messages')
        
    def has_only_one_value(l):
        if 0 == len(l):
            return False
        return len(l) == l.count(l[0])
    
    common_prob_power = has_only_one_value(best_sel_power_probs)

    if args.write:
        dst_dir = args.write
    elif selection_dir is not None:
        dst_dir = selection_dir
    
    max_repetitions_dict = {}
    msg_cnt = 0
    files = []
    for params in best_sel.values():
        out=[]
        out.append(['c',gen_mldsa_inputs.format_as_c(params)])
        out.append(['sv',gen_mldsa_inputs.format_as_sv(params)])
        out.append(['.sel.py',mldsa_select.params_to_str(params)])
        
        key = f"mldsa{params['mldsa_pset']}-m{gen_mldsa_inputs.size_str(params['msg_size'])}"
        max_repetitions_dict[key]=str(params['max_repetitions'])
        msg_cnt += len(params['indexes'])
        base_name = f"{key}-h{Utils.hexstr(params['sigs_sha256_digest'][:4],separator='')}"
        for o in out:
            name = os.path.join(dst_dir,base_name+'.'+o[0])
            files.append(name)
            with open(name,'w') as f:
                print(o[1],file=f)

    max_repetitions = []
    for pset in ['44','65','87']:
        for msize in ['69','10K','1M']:
            key = f"mldsa{pset}-m{msize}"
            if key in max_repetitions_dict:
                max_repetitions.append(max_repetitions_dict[key])
            else:
                max_repetitions.append('0')
    
    if common_prob_power:
        archive_name = f"mldsa-p{best_sel_power_probs[0]}-m{msg_cnt}-r{'-'.join(max_repetitions)}.tar.gz"
    else:
        archive_name = f"mldsa-max-repetition-m{msg_cnt}-r{'-'.join(max_repetitions)}.tar.gz"
    import tarfile 
    with tarfile.open(os.path.join(dst_dir,archive_name), 'w:gz') as archive:
        for f in files:
            archive.add(f,arcname = os.path.basename(f))