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

from mldsa_utils import gen_mldsa_inputs, gen_mldsa_outputs, size_str

def format_as_c(params, *,expand_msg=False):
    out = io.StringIO()
    def p(s,end='\n'):
        print(s,end=end,file=out)

    # Generate the inputs
    messages, mprimes, mus, _pk, _sk = gen_mldsa_inputs(params)

    # Output them as C variables
    def print_c_byte_array(name,dat,end='\n'):
        if name:
            decl = f'.{name} = '
            comma = ','
        else:
            decl = ''
            comma = ''
        p(f"{decl} {{{Utils.hexstr(dat,head='0x',separator=', ')}}}{comma}",end=end)

    def print_param_as_c_byte_array(name):
        dat = params[name]
        print_c_byte_array(name,dat)

    def print_c_ui_array(name,dat,end='\n'):
        if name:
            decl = f'.{name} = '
            comma = ','
        else:
            decl = ''
            comma = ''
        p(f"{decl} {{",end="")
        sep=""
        for e in dat:
            p(f"{sep}{e}",end="")
            sep=", "
        p(f"}}{comma}",end=end)

    def print_param_as_c_ui_array(name):
        dat = params[name]
        print_c_ui_array(name,dat)

    base_type_name = f"mldsa{params['mldsa_pset']}_m{size_str(len(messages[0]))}_test_vectors"

    #struct declaration
    nmessages = len(messages)
    message_size = len(messages[0])
    m_size = min(8,message_size)
    p(f"typedef struct {base_type_name}_struct {{")
    p(f'\tconst char* name;')
    p(f'\tunsigned int mldsa_pset;')
    p(f'\tuint8_t hdrbg_seed[8];')
    p(f'\tuint8_t mldsa_seed[32];')
    p(f"\tuint8_t sk[{len(params['sk'])}];")
    p(f"\tuint8_t pk[{len(params['pk'])}];")
    p(f'\tunsigned int nmessages;')
    p(f"\tunsigned int repetitions[{nmessages}];")
    p(f"\tunsigned int sib_bytes[{nmessages}];")
    p(f'\tunsigned int message_size;')
    p(f"\tuint8_t sign_messages[{nmessages}][{m_size}];")
    p(f'\tunsigned int internal_message_size;')
    p(f"\tuint8_t sign_internal_messages[{nmessages}][10];")
    p(f"\tuint8_t sign_external_mu[{nmessages}][64];")
    p(f'\tuint8_t sigs_sha256_digest[32];')
    p(f"}} {base_type_name}_t;")

    #value declaration
    p(f"const {base_type_name}_t {base_type_name} = {{")
    p(f'.name = "{gen_tv_name(params)}",')
    p(f".mldsa_pset = {params['mldsa_pset']},")
    print_param_as_c_byte_array('hdrbg_seed')
    print_param_as_c_byte_array('mldsa_seed')
    print_param_as_c_byte_array('sk')
    print_param_as_c_byte_array('pk')

    p(f".nmessages = {nmessages},")
    print_param_as_c_ui_array('repetitions')
    print_param_as_c_ui_array('sib_bytes')
    
    p(f'.message_size = {message_size},')
    mprime_size = message_size+2
    
    def decl_messages(name,data):
        p(f'.{name} = {{')
        for msg in data[:-1]:
            print_c_byte_array(None,msg,end=',\n')
        print_c_byte_array(None,data[-1],end='\n')
        p('},')

    if not expand_msg:
        for i in range(0,len(messages)):
            messages[i] = messages[i][0:8]
        for i in range(0,len(mprimes)):
            mprimes[i] = mprimes[i][0:10]

    # Input messages for ML-DSA.Sign
    decl_messages('sign_messages',messages)

    # Input messages for ML-DSA.Sign_Internal
    p(f'.internal_message_size = {mprime_size},')
    decl_messages('sign_internal_messages',mprimes)

    # Input messages for ML-DSA external Mu
    decl_messages('sign_external_mu',mus)

    print_param_as_c_byte_array('sigs_sha256_digest')
    p(f"}};")
    return out.getvalue()

def format_as_sv(params, *,expand_msg=False):
    out = io.StringIO()
    def p(s,end='\n'):
        print(s,end=end,file=out)
    # Generate the inputs
    messages, mprimes, mus, _pk, _sk = gen_mldsa_inputs(params)

    def int_as_sv_u64(name, v):
        if not isinstance(v,int):
            v = int.from_bytes(v,byteorder='little')
        if name:
            decl = f"logic [63:0] {name} = "
            comma = ';'
        else:
            decl = ""
            comma = ''
        return f"{decl}64'h{v:016x}{comma}"

    # Output them as SV variables
    def print_sv_array64(name,dat,end='\n'):
        nwords = (len(dat)+7)//8
        if name:
            p(f"localparam {name}_NWORDS = {nwords};")
            p(f'logic [{name}_NWORDS-1:0][63:0] {name} = ',end='')
            comma = ';'
        else:
            comma = ''
        p(f"'{{",end='')
        words = []
        for i in range(0,len(dat),8):
            words.insert(0,dat[i:i+8])
        sep = ''
        for w in words:
            p(f"{sep}{int_as_sv_u64(None,w)}",end='')
            sep=', '

        p(f"}}{comma}",end=end)

    def print_param_as_sv_u64(name):
        dat = params[name]
        p(int_as_sv_u64(name,dat))

    def print_param_as_sv_array64(name):
        dat = params[name]
        print_sv_array64(name,dat)

    p(f'localparam MLDSA_PSET = {params['mldsa_pset']};')
    print_param_as_sv_u64('hdrbg_seed')
    print_param_as_sv_array64('mldsa_seed')
    print_param_as_sv_array64('sk')
    print_param_as_sv_array64('pk')

    p(f'localparam N_MESSAGES = {len(messages)};')
    p(f'localparam MESSAGE_SIZE = {len(messages[0])};')
    mprime_size = len(messages[0])+2
    
    def decl_messages(name,data):
        nwords = (len(data[0])+7)//8
        p(f"logic [{nwords}-1:0][63:0] {name}[N_MESSAGES-1:0] = '{{")
        rdata = data[::-1] #create a copy of the list in reverse order
        for msg in rdata[:-1]:
            print_sv_array64(None,msg,end=',\n')
        print_sv_array64(None,rdata[-1],end='\n')
        p('};')

    if not expand_msg:
        for i in range(0,len(messages)):
            messages[i] = messages[i][0:8]
        for i in range(0,len(mprimes)):
            mprimes[i] = mprimes[i][0:10]

    # Input messages for ML-DSA.Sign
    decl_messages('sign_messages',messages)

    # Input messages for ML-DSA.Sign_Internal
    p(f'localparam INTERNAL_MESSAGE_SIZE = {mprime_size};')
    decl_messages('sign_internal_messages',mprimes)

    # Input messages for ML-DSA external Mu
    decl_messages('sign_external_mu',mus)

    print_param_as_sv_array64('sigs_sha256_digest')
    return out.getvalue()

def format_as_acvp_json(params, version=None):
    out = io.StringIO()
    def p(s,end='\n'):
        print(s,end=end,file=out)
    # Generate the inputs
    messages, _mprimes, _mus, pk, _sk = gen_mldsa_inputs(params)
    signatures = gen_mldsa_outputs(params)
    testGroup = {}
    testGroup["type"] = "MlDsaSign"
    testGroup["privateSeed"] = Utils.hexstr(params['mldsa_seed'],separator='')
    #testGroup["privateKeyPkcs8"] = ?
    #testGroup["publicKey"] = Utils.hexstr(pk,separator='')
    source = {"name": "https://github.com/sebastien-riou/BTVG-MLDSA" }
    if version:
        source["version"] = version
    testGroup["source"] = source
    tests = []
    for i in range(0,len(messages)):
        test = {}
        test["tcId"] = i+1
        test["msg"] = Utils.hexstr(messages[i],separator='')
        test["sig"] = Utils.hexstr(signatures[i],separator='')
        test["result"] = "valid"
        test["flags"] = ["ValidSignature"]
        tests.append(test)
    testGroup["tests"] = tests
    testGroups = []
    testGroups.append(testGroup)
    top = {}
    top["algorithm"] = f"ML-DSA-{params['mldsa_pset']}"
    top["numberOfTests"] = len(messages)
    top["schema"] = "mldsa_sign_seed_schema.json"
    top["testGroups"] = testGroups

    json.dump(top,out,indent=2)

    return out.getvalue()

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
    formats = ('ACVP', 'C', 'SV', 'ALL')
    parser.add_argument('--format', default='ACVP', choices=formats, help='output format')
    parser.add_argument('--expand-msg', help='Fully expand message input', action='store_true')
    parser.add_argument('--write', default='', help='Path to write result files', type=str)

    args = parser.parse_args()
    logformat = '%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s'
    logdatefmt = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(level=args.log_level, format=logformat, datefmt=logdatefmt)

    gen_acvp=False
    gen_c=False
    gen_sv=False
    match args.format:
        case 'ACVP':
            gen_acvp = True
        case 'C':
            gen_c = True
        case 'SV':
            gen_sv = True
        case 'ALL':
            gen_acvp = True
            gen_c = True
            gen_sv = True

    # Get the parameters
    params = runpy.run_path(args.params)
    
    out=[]
    if gen_acvp:
        out.append(['json',format_as_acvp_json(params)])
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
