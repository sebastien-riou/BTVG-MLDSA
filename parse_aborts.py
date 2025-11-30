import sys
import collections
import re
from pysatl import Utils

def parse_aborts(name):
    pattern_str = r"\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)"
    pattern = re.compile(pattern_str)

    records = []
    repetitions = []
    iterations = []
    out = dict()
    
    with open(name) as f:
        f.readline()
        out['hdrbg seed']=Utils.ba(f.readline())
        f.readline()
        out['mldsa seed']=Utils.ba(f.readline())
        f.readline()
        out['sk'] = Utils.ba(f.readline())
        f.readline()
        out['pk'] = Utils.ba(f.readline())
        out['mldsa pset'] = int(f.readline())
        out['ctx size'] = int(f.readline())
        out['msg size'] = int(f.readline())

    for line in open(name).readlines():
        m = pattern.match(line)
        if m:
            r = dict()
            iterations.append(int(m.group(1)))
            r['hdrbg_iteration'] = int(m.group(1))
            repetitions.append(int(m.group(2)))
            r['repetitions'] = int(m.group(2))
            r['aborts z'] = int(m.group(3))
            r['aborts r'] = int(m.group(4))
            r['aborts t0'] = int(m.group(5))
            r['aborts h'] = int(m.group(6))
            records.append(r)
            if r['aborts t0'] > 0:
                print(f'{r['aborts t0']} aborts t0')

    #print(f'{len(records)} records loaded')
    out['records'] = records 
    out['repetitions'] = repetitions
    out['iterations'] = iterations
    return out
