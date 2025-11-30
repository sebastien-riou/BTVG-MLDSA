import argparse
import logging
import os
import runpy
import hdrbg

from pysatl import Utils

import parse_aborts
import mldsa_select
import gen_mldsa_inputs

if __name__ == '__main__':
    scriptname = os.path.basename(__file__)
    scriptpath = os.path.dirname(__file__)
    parser = argparse.ArgumentParser(scriptname)
    levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    parser.add_argument('--log-level', default='INFO', choices=levels)
    psets = ('44', '65', '87')
    #parser.add_argument('--param-set', default=None, help='ML-DSA parameter set', choices=psets)
    #parser.add_argument('--msg-size', default=69, help='Message size', type=int)
    #parser.add_argument('--seed', default=None, help='Seed for the tool DRBG', type=int)
    parser.add_argument('--search', default=None, help='Path to result log files to search for high repetition cases (.log)', type=str)
    parser.add_argument('--read-log', default=None, help='Path to result log files already generated (.log)', type=str)
    parser.add_argument('--read-sel', default=None, help='Path to result selection files already generated (.sel.py)', type=str)
    parser.add_argument('--write', default=None, help='Path to write result files', type=str)
    
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
        print(f'Loading {len(result_files)} result files')
        for f in result_files:
            #print(f)
            data = parse_aborts.parse_aborts(f)
            if 0==len(data['records']):
                continue
            data['file'] = f
            key = f"{data['mldsa pset']}-{data['msg size']}"
            max_repetitions = max(data['repetitions'])
            index = data['repetitions'].index(max_repetitions)
            max_repetitions_iteration = data['iterations'][index]
            if key in best_data:
                best_max_repetitions = best_data[key]['max_repetitions']
            else:
                best_max_repetitions = 0
            if max_repetitions > best_max_repetitions:
                data['max_repetitions'] = max_repetitions
                data['max_repetitions_iteration'] = max_repetitions_iteration
                best_data[key] = data
                #print('new best')
            #print(f'mldsa{data['mldsa pset']} - msg size = {data['msg size']:7} - hdrbg seed = {Utils.hexstr(data['hdrbg seed'])} - max repetitions = {max_repetitions}')
        
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
    for key,data in best_sel.items():
        print(f'{key}-h{Utils.hexstr(data['sigs_sha256_digest'][:4],separator='')}: max repetitions = {data['max_repetitions']}, {len(data['indexes'])} messages')
        
    
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
    
    archive_name = f"mldsa-max-repetition-m{msg_cnt}-r{'-'.join(max_repetitions)}.tar.gz"
    import tarfile 
    with tarfile.open(archive_name, 'w:gz') as archive:
        for f in files:
            archive.add(f)